/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2009,2010,2011  Free Software Foundation, Inc.
 *  Copyright (c) 2010, 2012, Oracle and/or its affiliates. All rights reserved.
 *  Copyright (c) 2012 by Delphix. All rights reserved.
 *  Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 *  Copyright (c) 2014 by Toomas Soome.
 *
 *  GRUB is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/partition.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/zfs/zfs.h>
#include <grub/zfs/zio.h>
#include <grub/zfs/dnode.h>
#include <grub/zfs/uberblock_impl.h>
#include <grub/zfs/vdev_impl.h>
#include <grub/zfs/zio_checksum.h>
#include <grub/zfs/zap_impl.h>
#include <grub/zfs/zap_leaf.h>
#include <grub/zfs/zfs_znode.h>
#include <grub/zfs/dmu.h>
#include <grub/zfs/dmu_objset.h>
#include <grub/zfs/sa_impl.h>
#include <grub/zfs/dsl_dir.h>
#include <grub/zfs/dsl_dataset.h>
#include <grub/deflate.h>
#include <grub/crypto.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define	ZPOOL_PROP_BOOTFS		"bootfs"
#define	BOOTFSNAME_SIZE			256

/*
 * For nvlist manipulation. (from nvpair.h)
 */
#define	NV_ENCODE_NATIVE	0
#define	NV_ENCODE_XDR		1
#define	NV_BIG_ENDIAN	        0
#define	NV_LITTLE_ENDIAN	1
#define	DATA_TYPE_UINT64	8
#define	DATA_TYPE_STRING	9
#define	DATA_TYPE_NVLIST	19
#define	DATA_TYPE_NVLIST_ARRAY	20

#ifndef GRUB_UTIL
static grub_dl_t my_mod;
#endif

#define	P2PHASE(x, align)		((x) & ((align) - 1))
#ifndef	NBBY
#define	NBBY	8
#endif

static inline grub_disk_addr_t
DVA_OFFSET_TO_PHYS_SECTOR (grub_disk_addr_t offset)
{
  return ((offset + VDEV_LABEL_START_SIZE) >> SPA_MINBLOCKSHIFT);
}

/*
 * FAT ZAP data structures
 */
#define	ZFS_CRC64_POLY 0xC96C5795D7870F42ULL	/* ECMA-182, reflected form */
static inline grub_uint64_t
ZAP_HASH_IDX (grub_uint64_t hash, grub_uint64_t n)
{
  return (((n) == 0) ? 0 : ((hash) >> (64 - (n))));
}

#define	CHAIN_END	0xffff	/* end of the chunk chain */

/*
 * The amount of space within the chunk available for the array is:
 * chunk size - space for type (1) - space for next pointer (2)
 */
#define	ZAP_LEAF_ARRAY_BYTES (ZAP_LEAF_CHUNKSIZE - 3)

static inline int
ZAP_LEAF_HASH_SHIFT (int bs)
{
  return bs - 5;
}

static inline int
ZAP_LEAF_HASH_NUMENTRIES (int bs)
{
  return 1 << ZAP_LEAF_HASH_SHIFT(bs);
}

static inline grub_size_t
LEAF_HASH (int bs, grub_uint64_t h, zap_leaf_phys_t *l)
{
  return ((ZAP_LEAF_HASH_NUMENTRIES (bs)-1)
	  & ((h) >> (64 - ZAP_LEAF_HASH_SHIFT (bs) - l->l_hdr.lh_prefix_len)));
}

/*
 * The amount of space available for chunks is:
 * block size shift - hash entry size (2) * number of hash
 * entries - header space (2*chunksize)
 */
static inline int
ZAP_LEAF_NUMCHUNKS (int bs)
{
  return (((1U << bs) - 2 * ZAP_LEAF_HASH_NUMENTRIES (bs)) /
	  ZAP_LEAF_CHUNKSIZE - 2);
}

/*
 * The chunks start immediately after the hash table.  The end of the
 * hash table is at l_hash + HASH_NUMENTRIES, which we simply cast to a
 * chunk_t.
 */
static inline zap_leaf_chunk_t *
ZAP_LEAF_CHUNK (zap_leaf_phys_t *l, int bs, int idx)
{
  return &((zap_leaf_chunk_t *) (l->l_entries 
				 + (ZAP_LEAF_HASH_NUMENTRIES(bs) * 2)
				 / sizeof (grub_properly_aligned_t)))[idx];
}

static inline struct zap_leaf_entry *
ZAP_LEAF_ENTRY(zap_leaf_phys_t *l, int bs, int idx)
{
  return &ZAP_LEAF_CHUNK(l, bs, idx)->l_entry;
}


/*
 * Decompression Entry - lzjb & lz4
 */

extern grub_err_t lzjb_decompress (void *, void *, grub_size_t, grub_size_t);
extern grub_err_t lz4_decompress (void *, void *, grub_size_t, grub_size_t);

typedef grub_err_t zfs_decomp_func_t (void *s_start, void *d_start,
				      grub_size_t s_len, grub_size_t d_len);
typedef struct decomp_entry
{
  const char *name;
  zfs_decomp_func_t *decomp_func;
} decomp_entry_t;

/*
 * Signature for checksum functions.
 */
typedef void zio_checksum_t(const void *data, grub_uint64_t size, 
			    grub_zfs_endian_t endian, zio_cksum_t *zcp);

/*
 * Information about each checksum function.
 */
typedef struct zio_checksum_info {
	zio_checksum_t	*ci_func; /* checksum function for each byteorder */
	int		ci_correctable;	/* number of correctable bits	*/
	int		ci_eck;		/* uses zio embedded checksum? */
	const char		*ci_name;	/* descriptive name */
} zio_checksum_info_t;

typedef struct dnode_end
{
  dnode_phys_t dn;
  grub_zfs_endian_t endian;
} dnode_end_t;

struct grub_zfs_device_desc
{
  enum { DEVICE_LEAF, DEVICE_MIRROR, DEVICE_RAIDZ } type;
  enum { DEVICE_OK, DEVICE_ERROR } dev_state;
  grub_uint64_t id;
  grub_uint64_t guid;

  /* Valid only for non-leafs.  */
  unsigned n_children;
  struct grub_zfs_device_desc *children;

  /* Valid only for RAIDZ.  */
  unsigned nparity;

  /* Valid for all */
  unsigned ashift;
  unsigned max_children_ashift;

  /* Valid only for leaf devices.  */
  grub_device_t dev;
  grub_disk_addr_t vdev_phys_sector;
  uberblock_t current_uberblock;
  int original;
};

struct subvolume
{
  dnode_end_t mdn;
  grub_uint64_t obj;
  grub_uint64_t case_insensitive;
  grub_size_t nkeys;
  struct
  {
    grub_crypto_cipher_handle_t cipher;
    grub_uint64_t txg;
    grub_uint64_t algo;
  } *keyring;
};

struct grub_zfs_data
{
  int zcached; /* the value should be zero if no cache available */

  /* cache for a file block of the currently zfs_open()-ed file */
  char *file_buf;
  grub_uint64_t file_start;
  grub_uint64_t file_end;

  /* cache for a dnode block */
  dnode_phys_t *dnode_buf;
  dnode_phys_t *dnode_mdn;
  grub_uint64_t dnode_start;
  grub_uint64_t dnode_end;
  grub_zfs_endian_t dnode_endian;

  dnode_end_t mos;
  dnode_end_t dnode;
  struct subvolume subvol;

  struct grub_zfs_device_desc *devices_attached;
  unsigned n_devices_attached;
  unsigned n_devices_allocated;
  struct grub_zfs_device_desc *device_original;

  uberblock_t current_uberblock;

  int mounted;
  int mount_count;

  grub_uint64_t guid;
  char *dev_name;
};

/*
 * The following are taken straight from usr/src/uts/common/fs/zfs/vdev_raidz.c
 * If they change there, they need to be changed here.
 *
 * a map of columns returned for a given offset and size
 */
typedef struct raidz_col
{
  grub_uint64_t rc_devidx;	/* child device index for I/O */
  grub_uint64_t rc_offset;	/* device offset */
  grub_uint64_t rc_size;	/* I/O size */
  void *rc_data;		/* I/O data */
  void *rc_gdata;		/* used to store the "good" version */
  int rc_error;			/* I/O error for this device */
  grub_uint8_t rc_tried;	/* Did we attempt this I/O column? */
  grub_uint8_t rc_skipped;	/* Did we skip this I/O column? */
} raidz_col_t;

typedef struct raidz_map
{
  grub_uint64_t rm_cols;		/* Regular column count */
  grub_uint64_t rm_scols;		/* Count including skipped columns */
  grub_uint64_t rm_bigcols;		/* Number of oversized columns */
  grub_uint64_t rm_asize;		/* Actual total I/O size */
  grub_uint64_t rm_missingdata;		/* Count of missing data devices */
  grub_uint64_t rm_missingparity;	/* Count of missing parity devices */
  grub_uint64_t rm_firstdatacol;	/* First data column/parity count */
  grub_uint64_t rm_nskip;		/* Skipped sectors for padding */
  grub_uint64_t rm_skipstart;		/* Column index of padding start */
  void *rm_datacopy;			/* rm_asize-buffer of copied data */
  grub_addr_t rm_reports;		/* # of referencing checksum reports */
  grub_uint8_t rm_freed;		/* map no longer has referencing ZIO */
  grub_uint8_t rm_ecksuminjected;	/* checksum error was injected */
  raidz_col_t rm_col[1];		/* Flexible array of I/O columns */
} raidz_map_t;

/* cache list for ZFS mount */
struct zfs_mount_cache
{
  char *zcache_dev_name;
  unsigned long zcache_dev_id;
  struct grub_zfs_data *zcache_zfs_data;
  struct zfs_mount_cache *next;
} *zfs_mount_cache_list;

/* cache list for disk dev with ZFS uberblock being found */
struct zfs_dev_ublock
{
  char *dev_name;
  unsigned long dev_id;
  grub_uint64_t pool_id;
  grub_disk_addr_t vdev_phys_sector;
  uberblock_t current_uberblock;
  struct zfs_dev_ublock *next;
} *zfs_dev_ublock_list;

/* cache list for non-zfs disk dev */
struct zfs_dev_notzfs
{
  char *dev_name;
  unsigned long dev_id;
  struct zfs_dev_notzfs *next;
} *zfs_dev_notzfs_list;

/* Context for grub_zfs_dir.  */
struct grub_zfs_dir_ctx
{
  grub_fs_dir_hook_t hook;
  void *hook_data;
  struct grub_zfs_data *data;
};

grub_err_t (*grub_zfs_decrypt) (grub_crypto_cipher_handle_t cipher,
				grub_uint64_t algo,
				void *nonce,
				char *buf, grub_size_t size,
				const grub_uint32_t *expected_mac,
				grub_zfs_endian_t endian) = NULL;
grub_crypto_cipher_handle_t (*grub_zfs_load_key) (const struct grub_zfs_key *key,
						  grub_size_t keysize,
						  grub_uint64_t salt,
						  grub_uint64_t algo) = NULL;
/*
 * List of pool features that the grub implementation of ZFS supports for
 * read. Note that features that are only required for write do not need
 * to be listed here since grub opens pools in read-only mode.
 */
static const char *spa_feature_names[] = {
        "org.illumos:lz4_compress",
        "com.delphix:hole_birth",
        "com.delphix:extensible_dataset",
        "com.delphix:embedded_data",
	"org.open-zfs:large_blocks",
        NULL
};

static grub_err_t 
zlib_decompress (void *s, void *d,
		 grub_size_t slen, grub_size_t dlen)
{
  if (grub_zlib_decompress (s, slen, 0, d, dlen) < 0)
    return grub_errno;
  return GRUB_ERR_NONE;
}

static grub_err_t 
zle_decompress (void *s, void *d,
		grub_size_t slen, grub_size_t dlen)
{
  grub_uint8_t *iptr, *optr;
  grub_size_t clen;
  for (iptr = s, optr = d; iptr < (grub_uint8_t *) s + slen
	 && optr < (grub_uint8_t *) d + dlen;)
    {
      if (*iptr & 0x80)
	clen = ((*iptr) & 0x7f) + 0x41;
      else
	clen = ((*iptr) & 0x3f) + 1;
      if ((grub_ssize_t) clen > (grub_uint8_t *) d + dlen - optr)
	clen = (grub_uint8_t *) d + dlen - optr;
      if (*iptr & 0x40 || *iptr & 0x80)
	{
	  grub_memset (optr, 0, clen);
	  iptr++;
	  optr += clen;
	  continue;
	}
      if ((grub_ssize_t) clen > (grub_uint8_t *) s + slen - iptr - 1)
	clen = (grub_uint8_t *) s + slen - iptr - 1;
      grub_memcpy (optr, iptr + 1, clen);
      optr += clen;
      iptr += clen + 1;
    }
  if (optr < (grub_uint8_t *) d + dlen)
    grub_memset (optr, 0, (grub_uint8_t *) d + dlen - optr);
  return GRUB_ERR_NONE;
}

static decomp_entry_t decomp_table[ZIO_COMPRESS_FUNCTIONS] = {
  {"inherit", NULL},		/* ZIO_COMPRESS_INHERIT */
  {"on", lzjb_decompress},	/* ZIO_COMPRESS_ON */
  {"off", NULL},		/* ZIO_COMPRESS_OFF */
  {"lzjb", lzjb_decompress},	/* ZIO_COMPRESS_LZJB */
  {"empty", NULL},		/* ZIO_COMPRESS_EMPTY */
  {"gzip-1", zlib_decompress},  /* ZIO_COMPRESS_GZIP1 */
  {"gzip-2", zlib_decompress},  /* ZIO_COMPRESS_GZIP2 */
  {"gzip-3", zlib_decompress},  /* ZIO_COMPRESS_GZIP3 */
  {"gzip-4", zlib_decompress},  /* ZIO_COMPRESS_GZIP4 */
  {"gzip-5", zlib_decompress},  /* ZIO_COMPRESS_GZIP5 */
  {"gzip-6", zlib_decompress},  /* ZIO_COMPRESS_GZIP6 */
  {"gzip-7", zlib_decompress},  /* ZIO_COMPRESS_GZIP7 */
  {"gzip-8", zlib_decompress},  /* ZIO_COMPRESS_GZIP8 */
  {"gzip-9", zlib_decompress},  /* ZIO_COMPRESS_GZIP9 */
  {"zle", zle_decompress},      /* ZIO_COMPRESS_ZLE   */
  {"lz4", lz4_decompress},      /* ZIO_COMPRESS_LZ4   */
};

static grub_err_t zio_read_data (blkptr_t * bp, grub_zfs_endian_t endian,
				 void *buf, struct grub_zfs_data *data);
static grub_err_t zio_read_common (blkptr_t * bp, dva_t *dva,
				 grub_zfs_endian_t endian, void *buf,
				 struct grub_zfs_data *data);
static const char * nvlist_next_nvpair (const char *nvl, const char *nvpair);
static char *nvpair_name (const char *nvp);
static grub_err_t scan_devices (struct grub_zfs_data *data, grub_uint64_t id);

/*
 * Our own version of log2().  Same thing as highbit()-1.
 */
static int
zfs_log2 (grub_uint64_t num)
{
  int i = 0;

  while (num > 1)
    {
      i++;
      num = num >> 1;
    }

  return (i);
}

/* Checksum Functions */
static void
zio_checksum_off (const void *buf __attribute__ ((unused)),
		  grub_uint64_t size __attribute__ ((unused)),
		  grub_zfs_endian_t endian __attribute__ ((unused)),
		  zio_cksum_t * zcp)
{
  ZIO_SET_CHECKSUM (zcp, 0, 0, 0, 0);
}

/* Checksum Table and Values */
static zio_checksum_info_t zio_checksum_table[ZIO_CHECKSUM_FUNCTIONS] = {
  {NULL, 0, 0, "inherit"},
  {NULL, 0, 0, "on"},
  {zio_checksum_off, 0, 0, "off"},
  {zio_checksum_SHA256, 1, 1, "label"},
  {zio_checksum_SHA256, 1, 1, "gang_header"},
  {NULL, 0, 0, "zilog"},
  {fletcher_2, 0, 0, "fletcher2"},
  {fletcher_4, 1, 0, "fletcher4"},
  {zio_checksum_SHA256, 1, 0, "SHA256"},
  {NULL, 0, 0, "zilog2"},
  {zio_checksum_SHA256, 1, 0, "SHA256+MAC"},
};

/*
 * zio_checksum_verify: Provides support for checksum verification.
 *
 * Fletcher2, Fletcher4, and SHA256 are supported.
 *
 */
static grub_err_t
zio_checksum_verify (zio_cksum_t zc, grub_uint32_t checksum,
		     grub_zfs_endian_t endian, 
		     char *buf, grub_size_t size)
{
  zio_eck_t *zec = (zio_eck_t *) (buf + size) - 1;
  zio_checksum_info_t *ci = &zio_checksum_table[checksum];
  zio_cksum_t actual_cksum, expected_cksum;

  if (checksum >= ZIO_CHECKSUM_FUNCTIONS || ci->ci_func == NULL)
    {
      grub_dprintf ("zfs", "unknown checksum function %d\n", checksum);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
			 N_("unknown checksum function %d"), checksum);
    }

  if (ci->ci_eck)
    {
      expected_cksum = zec->zec_cksum;  
      zec->zec_cksum = zc;  
      ci->ci_func (buf, size, endian, &actual_cksum);
      zec->zec_cksum = expected_cksum;
      zc = expected_cksum;
    }
  else
    ci->ci_func (buf, size, endian, &actual_cksum);

  if (grub_memcmp (&actual_cksum, &zc,
		   checksum != ZIO_CHECKSUM_SHA256_MAC ? 32 : 20) != 0)
    {
      grub_dprintf ("zfs", "checksum %s verification failed\n", ci->ci_name);
      grub_dprintf ("zfs", "actual checksum %016llx %016llx %016llx %016llx\n",
		    (unsigned long long) actual_cksum.zc_word[0], 
		    (unsigned long long) actual_cksum.zc_word[1],
		    (unsigned long long) actual_cksum.zc_word[2], 
		    (unsigned long long) actual_cksum.zc_word[3]);
      grub_dprintf ("zfs", "expected checksum %016llx %016llx %016llx %016llx\n",
		    (unsigned long long) zc.zc_word[0], 
		    (unsigned long long) zc.zc_word[1],
		    (unsigned long long) zc.zc_word[2], 
		    (unsigned long long) zc.zc_word[3]);
      return grub_error (GRUB_ERR_BAD_FS, N_("checksum verification failed"));
    }

  return GRUB_ERR_NONE;
}

/*
 * vdev_uberblock_compare takes two uberblock structures and returns an integer
 * indicating the more recent of the two.
 * 	Return Value = 1 if ub2 is more recent
 * 	Return Value = -1 if ub1 is more recent
 * The most recent uberblock is determined using its transaction number and
 * timestamp.  The uberblock with the highest transaction number is
 * considered "newer".  If the transaction numbers of the two blocks match, the
 * timestamps are compared to determine the "newer" of the two.
 */
static int
vdev_uberblock_compare (uberblock_t * ub1, uberblock_t * ub2)
{
  grub_zfs_endian_t ub1_endian, ub2_endian;
  if (grub_zfs_to_cpu64 (ub1->ub_magic, GRUB_ZFS_LITTLE_ENDIAN)
      == UBERBLOCK_MAGIC)
    ub1_endian = GRUB_ZFS_LITTLE_ENDIAN;
  else
    ub1_endian = GRUB_ZFS_BIG_ENDIAN;
  if (grub_zfs_to_cpu64 (ub2->ub_magic, GRUB_ZFS_LITTLE_ENDIAN)
      == UBERBLOCK_MAGIC)
    ub2_endian = GRUB_ZFS_LITTLE_ENDIAN;
  else
    ub2_endian = GRUB_ZFS_BIG_ENDIAN;

  if (grub_zfs_to_cpu64 (ub1->ub_txg, ub1_endian) 
      < grub_zfs_to_cpu64 (ub2->ub_txg, ub2_endian))
    return (1);
  if (grub_zfs_to_cpu64 (ub1->ub_txg, ub1_endian) 
      > grub_zfs_to_cpu64 (ub2->ub_txg, ub2_endian))
    return (-1);

  if (grub_zfs_to_cpu64 (ub1->ub_timestamp, ub1_endian) 
      < grub_zfs_to_cpu64 (ub2->ub_timestamp, ub2_endian))
    return (1);
  if (grub_zfs_to_cpu64 (ub1->ub_timestamp, ub1_endian) 
      > grub_zfs_to_cpu64 (ub2->ub_timestamp, ub2_endian))
    return (-1);

  return (0);
}

/*
 * Three pieces of information are needed to verify an uberblock: the magic
 * number, the version number, and the checksum.
 *
 * Currently Implemented: version number, magic number, checksum
 *
 */
static grub_err_t
uberblock_verify (struct grub_zfs_device_desc *dev_desc, uberblock_t *uber,
    grub_uint64_t offset)
{
  grub_err_t err;
  grub_zfs_endian_t endian = GRUB_ZFS_UNKNOWN_ENDIAN;
  zio_cksum_t zc;

  if (grub_zfs_to_cpu64 (uber->ub_magic, GRUB_ZFS_LITTLE_ENDIAN)
      == UBERBLOCK_MAGIC
      && SPA_VERSION_IS_SUPPORTED(grub_zfs_to_cpu64 (uber->ub_version, GRUB_ZFS_LITTLE_ENDIAN)))
    endian = GRUB_ZFS_LITTLE_ENDIAN;

  if (grub_zfs_to_cpu64 (uber->ub_magic, GRUB_ZFS_BIG_ENDIAN) == UBERBLOCK_MAGIC
      && SPA_VERSION_IS_SUPPORTED(grub_zfs_to_cpu64 (uber->ub_version, GRUB_ZFS_BIG_ENDIAN)))
    endian = GRUB_ZFS_BIG_ENDIAN;

  if (endian == GRUB_ZFS_UNKNOWN_ENDIAN)
    return grub_error (GRUB_ERR_BAD_FS, N_("invalid uberblock magic"));

  grub_memset (&zc, 0, sizeof (zc));

  zc.zc_word[0] = grub_cpu_to_zfs64 (offset, endian);
  err = zio_checksum_verify (zc, ZIO_CHECKSUM_LABEL, endian,
			     (char *) uber, VDEV_UBERBLOCK_SIZE(dev_desc));

  return err;
}

/*
 * Find the best uberblock.
 * Return:
 *    Success - Pointer to the best uberblock.
 *    Failure - NULL
 */
static uberblock_t *
find_bestub (struct grub_zfs_device_desc *dev_desc, grub_uint8_t *ub_array,
	     grub_disk_addr_t sector)
{
  uberblock_t *ubbest = NULL;
  grub_uint64_t i;
  grub_disk_addr_t offset;
  grub_err_t err = GRUB_ERR_NONE;

  for (i = 0; i < (grub_uint64_t)VDEV_UBERBLOCK_RING; i += (1ULL << VDEV_UBERBLOCK_SHIFT(dev_desc)))
    {
      offset = (sector << SPA_MINBLOCKSHIFT) + VDEV_PHYS_SIZE + i;

      err = uberblock_verify (dev_desc, (uberblock_t *)&ub_array[i], offset);
      if (err)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      if (ubbest == NULL 
	  || vdev_uberblock_compare ((uberblock_t *)&ub_array[i], ubbest) < 0)
	ubbest = (uberblock_t *)&ub_array[i];
    }
  if (!ubbest)
    grub_errno = err;

  return (ubbest);
}

static inline grub_size_t
get_psize (blkptr_t * bp, grub_zfs_endian_t endian)
{
  return ((((grub_zfs_to_cpu64 ((bp)->blk_prop, endian) >> 16) & 0xffff) + 1)
	  << SPA_MINBLOCKSHIFT);
}

static grub_uint64_t
dva_get_offset (const dva_t *dva, grub_zfs_endian_t endian)
{
  grub_dprintf ("zfs", "dva=%llx, %llx asize=%llx\n", 
		(unsigned long long) dva->dva_word[0], 
		(unsigned long long) dva->dva_word[1],
		(unsigned long long) DVA_GET_ASIZE(dva));
  return grub_zfs_to_cpu64 ((dva)->dva_word[1], 
			    endian) << SPA_MINBLOCKSHIFT;
}

static grub_err_t
zfs_fetch_nvlist (struct grub_zfs_device_desc *diskdesc, char **nvlist)
{
  grub_err_t err;

  if (!diskdesc->dev)
    return grub_error (GRUB_ERR_BAD_FS, N_("member drive unknown"));

  *nvlist = grub_malloc (VDEV_PHYS_SIZE);

  /* Read in the vdev name-value pair list (112K). */
  grub_dprintf("zfs", "read: sector %llx size %x\n", (unsigned long long)
               diskdesc->vdev_phys_sector, VDEV_PHYS_SIZE);
  err = grub_disk_read (diskdesc->dev->disk, diskdesc->vdev_phys_sector, 0,
			VDEV_PHYS_SIZE, *nvlist);
  if (err)
    {
      grub_dprintf("zfs", "grub_disk_read failed with err = %d\n", err);
      grub_free (*nvlist);
      *nvlist = 0;
      return err;
    }
  return GRUB_ERR_NONE;
}

/*
 * Check if this vdev is online and is in a good state.
 */
int
grub_zfs_vdev_validate (const char *nv)
{
  grub_uint64_t ival = 0;

  if (grub_zfs_nvlist_lookup_uint64 (nv, ZPOOL_CONFIG_OFFLINE, &ival) && ival)
    {
      grub_dprintf ("zfs", "vdev_validate: ZPOOL_CONFIG_OFFLINE\n");
      return (1);
    }
  if ((grub_zfs_nvlist_lookup_uint64 (nv, ZPOOL_CONFIG_FAULTED, &ival) && ival) &&
      !(grub_zfs_nvlist_lookup_uint64 (nv, ZPOOL_CONFIG_DEGRADED, &ival) && ival))
    {
      grub_dprintf ("zfs", "vdev_validate: ZPOOL_CONFIG_FAULTED\n");
      return (1);
    }
  if (grub_zfs_nvlist_lookup_uint64 (nv, ZPOOL_CONFIG_REMOVED, &ival) && ival)
    {
      grub_dprintf ("zfs", "vdev_validate: ZPOOL_CONFIG_REMOVED\n");
      return (1);
    }

    return (0);
}

static grub_err_t
fill_vdev_info_real (struct grub_zfs_data *data,
		     const char *nvlist,
		     struct grub_zfs_device_desc *fill,
		     struct grub_zfs_device_desc *insert,
		     int *inserted)
{
  char *type;

  type = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_TYPE);
  grub_dprintf("zfs", "type = %s\n", type ? : "(null)");

  if (!type)
    return grub_errno;

  if (!grub_zfs_nvlist_lookup_uint64 (nvlist, "id", &(fill->id)))
    {
      grub_free (type);
      return grub_error (GRUB_ERR_BAD_FS, N_("couldn't find vdev id"));
    }

  if (!grub_zfs_nvlist_lookup_uint64 (nvlist, "guid", &(fill->guid)))
    {
      grub_free (type);
      return grub_error (GRUB_ERR_BAD_FS, N_("couldn't find vdev guid"));
    }

  fill->max_children_ashift = 0;

  if (grub_strcmp (type, VDEV_TYPE_DISK) == 0
      || grub_strcmp (type, VDEV_TYPE_FILE) == 0)
    {
      grub_uint64_t ashift;
      fill->type = DEVICE_LEAF;
      if (!grub_zfs_nvlist_lookup_uint64 (nvlist, "ashift", &ashift))
        {
	  fill->ashift = UBERBLOCK_SHIFT;
        }
      else
	  fill->ashift = ashift;

      grub_dprintf("zfs", "fill->dev=%p fill->guid=%llx insert->guid=%llx insert->dev=%p ashift=%d\n",
                    fill->dev, (unsigned long long)fill->guid, 
                    (unsigned long long)insert->guid, insert->dev, fill->ashift);
      if (!fill->dev && fill->guid == insert->guid)
	{
	  fill->dev = insert->dev;
	  fill->vdev_phys_sector = insert->vdev_phys_sector;
	  fill->current_uberblock = insert->current_uberblock;
	  fill->original = insert->original;
	  *inserted = 1;
	}
      if (fill->guid == insert->guid && !data->device_original)
        data->device_original = fill;

      if (grub_zfs_vdev_validate(nvlist))
        fill->dev_state = DEVICE_ERROR;
      else
        fill->dev_state = DEVICE_OK;

      grub_free (type);

      return GRUB_ERR_NONE;
    }

  if (grub_strcmp (type, VDEV_TYPE_MIRROR) == 0
      || grub_strcmp (type, VDEV_TYPE_RAIDZ) == 0)
    {
      int nelm, i;

      if (grub_strcmp (type, VDEV_TYPE_MIRROR) == 0)
	fill->type = DEVICE_MIRROR;
      else
	{
	  grub_uint64_t par;
	  fill->type = DEVICE_RAIDZ;
	  if (!grub_zfs_nvlist_lookup_uint64 (nvlist, "nparity", &par))
	    {
	      grub_free (type);
	      return grub_error (GRUB_ERR_BAD_FS, N_("couldn't find raidz parity"));
	    }
	  fill->nparity = par;
          if (!grub_zfs_nvlist_lookup_uint64 (nvlist, "ashift", &par))
            {
              grub_free (type);
              return grub_error (GRUB_ERR_BAD_FS, N_("couldn't find raidz ashift"));
            }
          fill->ashift = par;
	}

      nelm = grub_zfs_nvlist_lookup_nvlist_array_get_nelm (nvlist,
							   ZPOOL_CONFIG_CHILDREN);

      if (nelm <= 0)
	{
	  grub_free (type);
	  return grub_error (GRUB_ERR_BAD_FS, N_("incorrect mirror VDEV"));
	}

      if (!fill->children)
	{
	  fill->n_children = nelm;
	  
	  fill->children = grub_zalloc (fill->n_children
					* sizeof (fill->children[0]));
	}

      for (i = 0; i < nelm; i++)
	{
	  char *child;
	  grub_err_t err;

	  child = grub_zfs_nvlist_lookup_nvlist_array
	    (nvlist, ZPOOL_CONFIG_CHILDREN, i);
          if (! child)
            {
              grub_free(type);
              return grub_errno;
            }

	    err = fill_vdev_info_real (data, child, &fill->children[i],
				       insert, inserted);
	    grub_dprintf("zfs", "Child %d: fill returned %d inserted: %d\n",
			 i, err, *inserted);

	  grub_free (child);

	  if (err)
	    {
	      grub_free (type);
	      return err;
	    }
	  if (fill->children[i].ashift > fill->max_children_ashift)
	    fill->max_children_ashift = fill->children[i].ashift;
	}
      if (*inserted == 0)
	{
	  grub_free (type);
	  return GRUB_ERR_NONE;
	}

      for (i = 0; i < nelm; i++)
	{
	  char *child;

	  child = grub_zfs_nvlist_lookup_nvlist_array
	    (nvlist, ZPOOL_CONFIG_CHILDREN, i);
          if (! child)
            {
              grub_free(type);
              return grub_errno;
            }
	  if (fill->children[i].dev == NULL)
	    {
	      grub_uint64_t cid;
	      if (grub_zfs_nvlist_lookup_uint64 (nvlist, "id", &cid))
	        scan_devices(data, cid);
	    }

	  grub_free (child);
	}
      grub_free (type);
      return GRUB_ERR_NONE;
    }

  grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "vdev %s isn't supported", type);
  grub_free (type);
  return grub_errno;
}

static grub_err_t
fill_vdev_info (struct grub_zfs_data *data,
		char *nvlist, struct grub_zfs_device_desc *diskdesc,
		int *inserted)
{
  grub_uint64_t id;
  unsigned i;

  *inserted = 0;
  if (!grub_zfs_nvlist_lookup_uint64 (nvlist, "id", &id)) {
    grub_dprintf("zfs", "nvlist lookup of id failed\n");
    return grub_error (GRUB_ERR_BAD_FS, "couldn't find vdev id");
  }

  grub_dprintf("zfs", "nvlist lookup of id => 0x%llx\n",
               (unsigned long long)id);

  for (i = 0; i < data->n_devices_attached; i++)
    if (data->devices_attached[i].id == id)
      return fill_vdev_info_real (data, nvlist, &data->devices_attached[i],
				  diskdesc, inserted);

  data->n_devices_attached++;
  if (data->n_devices_attached > data->n_devices_allocated)
    {
      void *tmp = data->devices_attached;
      unsigned num = 2 * data->n_devices_attached + 1;

      data->devices_attached
	= grub_realloc (tmp, num * sizeof (data->devices_attached[0]));
      if (data->devices_attached == tmp)
	{
	  data->devices_attached = tmp;
	  return grub_errno;
	}
      data->n_devices_allocated = num;
    }

  grub_memset (&data->devices_attached[data->n_devices_attached - 1],
	       0, sizeof (data->devices_attached[data->n_devices_attached - 1]));

  return fill_vdev_info_real (data, nvlist,
			      &data->devices_attached[data->n_devices_attached - 1],
			      diskdesc, inserted);
}

static int
check_feature(const char *name, grub_uint64_t val,
	      struct grub_zfs_dir_ctx *ctx __attribute__((unused)))
{
	int i;

	if (val == 0)	/* value is not set */
		return (0);
	if(name[0] == 0)  /* empty name */
		return (0);

	for (i = 0; spa_feature_names[i] != NULL; i++ )
		if (grub_strcmp(name, spa_feature_names[i]) == 0)
			return (0);
	return grub_error(GRUB_ERR_NOT_IMPLEMENTED_YET,
			    "unknown feature: %s", name);
}

static grub_err_t
zfs_pool_validate(struct grub_zfs_device_desc *diskdesc,
		  grub_uint64_t *poolguid, char **ret_nvlist)
{
  grub_uint64_t pool_state, txg = 0;
  char *nvlist, *features;
  grub_uint64_t version;
  int found;
  grub_err_t err;
  grub_zfs_endian_t endian;
  vdev_phys_t *phys;
  zio_cksum_t emptycksum;

  err = zfs_fetch_nvlist (diskdesc, &nvlist);
  if (err) {
    grub_dprintf("zfs", "zfs_fetch_nvlist failed\n");
    return err;
  }

  phys = (vdev_phys_t*) nvlist;
  if (grub_zfs_to_cpu64 (phys->vp_zbt.zec_magic, GRUB_ZFS_LITTLE_ENDIAN)
      == ZEC_MAGIC)
    endian = GRUB_ZFS_LITTLE_ENDIAN;
  else if (grub_zfs_to_cpu64 (phys->vp_zbt.zec_magic, GRUB_ZFS_BIG_ENDIAN)
	   == ZEC_MAGIC)
    endian = GRUB_ZFS_BIG_ENDIAN;
  else
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_BAD_FS,
			 "bad vdev_phys_t.vp_zbt.zec_magic number");
    }

  /* Now check the integrity of the vdev_phys_t structure though checksum.  */
  ZIO_SET_CHECKSUM(&emptycksum, diskdesc->vdev_phys_sector << diskdesc->ashift,
		   0, 0, 0);
  err = zio_checksum_verify (emptycksum, ZIO_CHECKSUM_LABEL, endian,
			     nvlist, VDEV_PHYS_SIZE);
  if (err) {
    grub_dprintf("zfs", "zio_checksum_verify failed\n");
    return err;
  }

  grub_dprintf ("zfs", "check 2 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_STATE,
					 &pool_state);
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_POOL_STATE " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 3 passed\n");

  if (pool_state == POOL_STATE_DESTROYED)
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_BAD_FS, "zpool is marked as destroyed");
    }
  grub_dprintf ("zfs", "check 4 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_TXG, &txg);
  if (!found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_POOL_TXG " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 6 passed\n");

  /* not an active device */
  if (txg == 0)
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_BAD_FS, "zpool isn't active");
    }
  grub_dprintf ("zfs", "check 7 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_VERSION,
					 &version);
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_VERSION " not found");
      return grub_errno;
    }
  grub_dprintf ("zfs", "check 8 passed\n");

  if (!SPA_VERSION_IS_SUPPORTED(version))
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
	"ZFS SPA version %llu is not compatible with this GRUB2 ZFS "
	"reader code.\nSupported Oracle ZFS is %llu\n"
	"Supported OpenZFS version is %llu\n",
	(unsigned long long) version,
	(unsigned long long) SPA_VERSION_ORACLE,
	(unsigned long long) SPA_VERSION);
    }
  grub_dprintf ("zfs", "check 9 passed\n");

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_GUID,
					 &(diskdesc->guid));
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_GUID " not found");
      return grub_errno;
    }

  found = grub_zfs_nvlist_lookup_uint64 (nvlist, ZPOOL_CONFIG_POOL_GUID,
					 poolguid);
  if (! found)
    {
      grub_free (nvlist);
      if (! grub_errno)
	grub_error (GRUB_ERR_BAD_FS, ZPOOL_CONFIG_POOL_GUID " not found");
      return grub_errno;
    }

  grub_dprintf ("zfs", "check 10 passed\n");

  features = grub_zfs_nvlist_lookup_nvlist (nvlist,
					    ZPOOL_CONFIG_FEATURES_FOR_READ);
  if (features)
    {
      const char *nvp;
      char *name;

      for (nvp = nvlist_next_nvpair(features, NULL); nvp != NULL;
           nvp = nvlist_next_nvpair(features, nvp)) {
        name = nvpair_name(nvp);
        if (name) {
          err = check_feature(name, 1, NULL);
          if (err) {
            grub_free (name);
            grub_free (features);
            grub_free (nvlist);
            return (err);
          }
          grub_free (name);
	}
      }
      grub_free (features);
    }

  grub_dprintf ("zfs", "check 11 passed\n");
  if (ret_nvlist == NULL)
    grub_free (nvlist);
  else
    *ret_nvlist = nvlist;
  return (GRUB_ERR_NONE);
}

/*
 * Check the disk label information and retrieve needed vdev name-value pairs.
 */
static grub_err_t
check_pool_label (struct grub_zfs_data *data,
		  struct grub_zfs_device_desc *diskdesc,
		  int *inserted, int original)
{
  grub_uint64_t poolguid;
  grub_err_t err;
  char *nvlist = NULL;
  char *nv;

  *inserted = 0;

  err = zfs_pool_validate(diskdesc, &poolguid, &nvlist);
  if (err)
    return err;

  if (original)
    data->guid = poolguid;

  if (data->guid != poolguid)
    {
      grub_free (nvlist);
      return grub_error (GRUB_ERR_BAD_FS, "another zpool");
    }

  nv = grub_zfs_nvlist_lookup_nvlist (nvlist, ZPOOL_CONFIG_VDEV_TREE);

  if (!nv)
    {
      grub_free (nvlist);
      grub_dprintf("zfs", "Couldn't find vdev tree\n");
      return grub_error (GRUB_ERR_BAD_FS, N_("couldn't find vdev tree"));
    }
  err = fill_vdev_info (data, nv, diskdesc, inserted);

  if (err)
    {
      grub_free (nv);
      grub_free (nvlist);
      grub_dprintf("zfs", "fill_vdev_info() failed: %d\n", err);
      return (err);
    }
  grub_dprintf ("zfs", "done filling in vdev info\n");

  grub_free (nv);
  grub_free (nvlist);

  return (GRUB_ERR_NONE);
}

static int
vdev_is_pool_member(struct grub_zfs_data *data, grub_uint64_t *vdev_guid)
{
  unsigned int i, j;
  int ret = 0;

  for (i = 0; ret == 0 && i < data->n_devices_attached; i++)
    {
grub_dprintf("zfs", "vdev_is_pool_member: type = %s\n",
 (data->devices_attached[i].type == DEVICE_LEAF) ? "leaf" :
  ((data->devices_attached[i].type == DEVICE_MIRROR) ? "mirror" :
  ((data->devices_attached[i].type == DEVICE_RAIDZ) ? "raidz" : "unknown")));

      if (data->devices_attached[i].type == DEVICE_LEAF)
        {
grub_dprintf("zfs", "vdev_guid = 0x%llx | device[%d].guid = 0x%llx\n",
(unsigned long long)*vdev_guid,
i,
(unsigned long long)data->devices_attached[i].guid);
          ret = (*vdev_guid == data->devices_attached[i].guid);
          break;
        }
      else if (data->devices_attached[i].type == DEVICE_MIRROR ||
	       data->devices_attached[i].type == DEVICE_RAIDZ)
        {
          for (j = 0; j < data->devices_attached[i].n_children; j++)
            {
grub_dprintf("zfs", "vdev_guid = 0x%llx | device[%d].c[%d]guid = 0x%llx\n",
(unsigned long long)*vdev_guid,
i, j,
(unsigned long long)data->devices_attached[i].children[j].guid);
              if (*vdev_guid == data->devices_attached[i].children[j].guid)
                {
                  ret = 1;
                  break;
                }
            }
        }
    }

    grub_dprintf("zfs", "vdev_is_pool_member: returning %d\n", ret);
    return (ret);
}

static grub_uint64_t
zfs_get_poolprop_ashift(struct grub_zfs_device_desc *dev_desc)
{
  grub_err_t err;
  grub_uint64_t ashift = UBERBLOCK_SHIFT;
  char *nvlist, *vdev_nv;

  err = zfs_fetch_nvlist (dev_desc, &nvlist);
  if (!err) {
    vdev_nv = grub_zfs_nvlist_lookup_nvlist (nvlist, ZPOOL_CONFIG_VDEV_TREE);
    if (vdev_nv) {
      err = grub_zfs_nvlist_lookup_uint64 (vdev_nv, "ashift", &ashift);
      grub_free(vdev_nv);
    }
    grub_free(nvlist);
    grub_dprintf("zfs", "Using ashift = %u\n", (unsigned)ashift);
  } else
    grub_dprintf("zfs", "ashift nvlist lookup failed\n");

  return ashift;
}

struct find_better_ctx {
	struct grub_zfs_data *data;
	uberblock_t *ub_array;
	int *better_found;
};

static int
find_better_vdev_iter (const char *name, void *hook_data)
{
	struct find_better_ctx *ctx = hook_data;
	struct grub_zfs_data *data = ctx->data;
	uberblock_t *ub_array = ctx->ub_array;
	int *better_found = ctx->better_found;
	int label = 0, vdevnum = VDEV_LABELS;
	uberblock_t *ubbest = NULL;
	grub_device_t dev;
	grub_err_t err;
	struct grub_zfs_device_desc desc;
	struct zfs_dev_notzfs *dev_notzfs;
	struct zfs_dev_ublock *dev_ub;
	grub_uint64_t poolguid;
	char *partname, *partname_new;

	if (grub_strncmp(name, "fd", 2) == 0)
		return 0;

	/* search cached non-zfs disk */
	for (dev_notzfs = zfs_dev_notzfs_list;
	    dev_notzfs != NULL; dev_notzfs = dev_notzfs->next)
		if (grub_strcmp(name, dev_notzfs->dev_name) == 0) {
			grub_dprintf("zfs", "find_better_vdev_iter: "
			    "found cached non-zfs disk dev: %s\n",
			    dev_notzfs->dev_name);
			return 0;
		}

	dev = grub_device_open(name);
	if (!dev)
		return 0;

	/* the mirrored root pool should be on other disk(s) */
	if (!dev->disk ||
	    dev->disk->id == data->device_original->dev->disk->id) {
		grub_device_close(dev);
		return 0;
	}

	/* the partition name for the mirrored root pool should be same */
	partname = grub_partition_get_name(
	    data->device_original->dev->disk->partition);
	partname_new = grub_partition_get_name(dev->disk->partition);
	if (!(((partname == NULL) && (partname_new == NULL)) ||
	    (partname && partname_new &&
	     grub_strcmp(partname_new, partname) == 0))) {
		grub_free(partname);
		grub_free(partname_new);
		grub_device_close(dev);
		return 0;
	}
	grub_free(partname);
	grub_free(partname_new);

	grub_dprintf("zfs", "find_better_vdev: Trying %s\n", name);

	desc.dev = dev;

	for (dev_ub = zfs_dev_ublock_list; dev_ub != NULL;
	    dev_ub = dev_ub->next)
		if (grub_strcmp(name, dev_ub->dev_name) == 0) {
			if (data->guid != dev_ub->pool_id) {
				grub_device_close(dev);
				return 0;
			} else {
				grub_dprintf("zfs",
				    "find_better_vdev: cached dev_ub for %s\n",
				    dev_ub->dev_name);
				grub_device_close(dev);
				if (vdev_uberblock_compare(
				    &data->current_uberblock,
				    &dev_ub->current_uberblock) > 0) {
					grub_dprintf("zfs",
					    "Better uberblock found!!!\n");
					*better_found = 1;
					return 1; /* Terminate iteration */
				} else
					return 0;
			}
		}
    
	/* Don't check back labels on CDROM.  */
	if (grub_disk_get_size(dev->disk) == GRUB_DISK_SIZE_UNKNOWN)
		vdevnum = VDEV_LABELS / 2;

	for (label = 0; ubbest == NULL && label < vdevnum; label++) {
		desc.vdev_phys_sector
		    = label * (sizeof (vdev_label_t) >> SPA_MINBLOCKSHIFT)
			+ ((VDEV_SKIP_SIZE + VDEV_BOOT_HEADER_SIZE)
			>> SPA_MINBLOCKSHIFT)
		    + (label < VDEV_LABELS / 2 ? 0 :
			grub_disk_get_size(dev->disk)
		    - VDEV_LABELS *
			(sizeof (vdev_label_t) >> SPA_MINBLOCKSHIFT));

		/* Read in the uberblock ring (128K). */
		err = grub_disk_read(dev->disk, desc.vdev_phys_sector
		    + (VDEV_PHYS_SIZE >> SPA_MINBLOCKSHIFT), 0,
		    VDEV_UBERBLOCK_RING, (char *) ub_array);
		if (err) {
			grub_dprintf ("zfs",
			    "find_better_vdev: grub_disk_read() failed\n");
			grub_errno = GRUB_ERR_NONE;
			continue;
		}
		grub_dprintf("zfs", "label ok %d\n", label);

		/*
		 * Make sure that ashift is filled in desc before calling
		 * find_bestub
		 */
		desc.ashift = zfs_get_poolprop_ashift(&desc);

		ubbest = find_bestub(&desc, (grub_uint8_t *)ub_array,
		    desc.vdev_phys_sector);
		if (!ubbest) {
			grub_dprintf ("zfs",
			    "find_better_vdev: No uberblock found\n");
			grub_errno = GRUB_ERR_NONE;
			continue;
		}

		grub_memmove (&(desc.current_uberblock), ubbest,
		    sizeof (uberblock_t));

		err = zfs_pool_validate (&desc, &poolguid, NULL);
		if (err) {
			grub_dprintf("zfs",
			    "zfs_pool_validate of dev=`%s' failed: %d\n",
			    desc.dev->disk->name, err);
			grub_errno = GRUB_ERR_NONE;
			continue;
		}

		dev_ub = grub_malloc(sizeof (struct zfs_dev_ublock));
		if (dev_ub) {
			dev_ub->dev_name = grub_strdup(name);
			dev_ub->dev_id = dev->disk->id;
			dev_ub->pool_id = poolguid;
			dev_ub->vdev_phys_sector = desc.vdev_phys_sector;
			grub_memmove(&(dev_ub->current_uberblock), ubbest,
			    sizeof (uberblock_t));
			if (zfs_dev_ublock_list)
				dev_ub->next = zfs_dev_ublock_list;
			else
				dev_ub->next = NULL;
			zfs_dev_ublock_list = dev_ub;
		}

		if (data->guid != poolguid ||
		    !vdev_is_pool_member(data, &desc.guid)) {
			grub_dprintf("zfs",
			    "pool guid 0x%llx not matched for disk dev %s\n",
			    (unsigned long long) poolguid,
			    desc.dev->disk->name);
			grub_device_close (dev);
			return 0;
		}

		/*
		 * zfs_pool_validate() has the side effect of filling in the
		 * VDEV guid for this VDEV, so ensure that this VDEV is a
		 * member of the pool.
		 */
		if (vdev_uberblock_compare(&data->current_uberblock, ubbest)
		    > 0) {
			grub_dprintf("zfs", "Better uberblock found!\n");
			grub_device_close (dev);
			*better_found = 1;
			return 1; /* Terminate iteration */
		} else {
			grub_device_close (dev);
			return 0;
		}
	}

	dev_notzfs = grub_malloc(sizeof (struct zfs_dev_notzfs));
	if (dev_notzfs) {
		dev_notzfs->dev_name = grub_strdup(name);
		dev_notzfs->dev_id = dev->disk->id;
		if (zfs_dev_notzfs_list)
			dev_notzfs->next = zfs_dev_notzfs_list;
		else
			dev_notzfs->next = NULL;
		zfs_dev_notzfs_list = dev_notzfs;
	}
 
	grub_device_close(dev);
	return 0;
}

static grub_err_t
find_better_vdev(struct grub_zfs_data *data, int *better_found)
{
  struct find_better_ctx ctx;

  *better_found = 0;
  ctx.data = data;
  ctx.better_found = better_found;
  ctx.ub_array = grub_malloc (VDEV_UBERBLOCK_RING);
  if (!ctx.ub_array)
    return grub_errno;

  grub_device_iterate (find_better_vdev_iter, (void *) &ctx);
  grub_free (ctx.ub_array);
  return GRUB_ERR_NONE;
}

static grub_err_t
scan_disk (grub_device_t dev, struct grub_zfs_data *data,
	   int original, int *inserted)
{
  int label = 0;
  int better_found = 0;
  uberblock_t *ub_array, *ubbest = NULL;
  grub_err_t err;
  int vdevnum;
  struct grub_zfs_device_desc desc;
  struct zfs_dev_notzfs *dev_notzfs;
  struct zfs_dev_ublock *dev_ub = NULL;

  /* search for cached non-zfs dev first */
  for (dev_notzfs = zfs_dev_notzfs_list; dev_notzfs != NULL; dev_notzfs = dev_notzfs->next)
    if (grub_strcmp (data->dev_name, dev_notzfs->dev_name) == 0)
      {
        grub_dprintf("zfs", "scan_disk: found cached non-zfs disk dev: %s\n", dev_notzfs->dev_name);
        return grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid ZFS label");
     }

  ub_array = grub_malloc (VDEV_UBERBLOCK_RING);
  if (!ub_array)
  {
    grub_dprintf("zfs", "ub_array allocation failed.\n");
    return grub_errno;
  }

  vdevnum = VDEV_LABELS;

  desc.dev = dev;
  desc.original = original;

  if (original)
    {
      for (dev_ub = zfs_dev_ublock_list; dev_ub != NULL; dev_ub = dev_ub->next)
        if (grub_strcmp (data->dev_name, dev_ub->dev_name) == 0)
          {
            grub_dprintf("zfs", "scan_disk: found cached dev_ub for %s\n", dev_ub->dev_name);
            desc.vdev_phys_sector = dev_ub->vdev_phys_sector;
            grub_memmove (&(desc.current_uberblock),
                          &dev_ub->current_uberblock, sizeof (uberblock_t));
            grub_memmove (&(data->current_uberblock),
                          &dev_ub->current_uberblock, sizeof (uberblock_t));
            desc.ashift = zfs_get_poolprop_ashift(&desc);
            goto check_label;
          }
   }

  /* Don't check back labels on CDROM.  */
  if (grub_disk_get_size (dev->disk) == GRUB_DISK_SIZE_UNKNOWN)
    vdevnum = VDEV_LABELS / 2;

  for (label = 0; ubbest == NULL && label < vdevnum; label++)
    {
      desc.vdev_phys_sector
	= label * (sizeof (vdev_label_t) >> SPA_MINBLOCKSHIFT)
	+ ((VDEV_SKIP_SIZE + VDEV_BOOT_HEADER_SIZE) >> SPA_MINBLOCKSHIFT)
	+ (label < VDEV_LABELS / 2 ? 0 : grub_disk_get_size (dev->disk)
	   - VDEV_LABELS * (sizeof (vdev_label_t) >> SPA_MINBLOCKSHIFT));

      /* Read in the uberblock ring (128K). */
      err = grub_disk_read (dev->disk, desc.vdev_phys_sector
			    + (VDEV_PHYS_SIZE >> SPA_MINBLOCKSHIFT),
			    0, VDEV_UBERBLOCK_RING, (char *) ub_array);
      if (err)
	{
	  grub_dprintf ("zfs", "scan_disk: grub_disk_read() failed\n");
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      grub_dprintf ("zfs", "label ok %d\n", label);

      /* Make sure that ashift is filled in desc before calling find_bestub */
      desc.ashift = zfs_get_poolprop_ashift(&desc);

      ubbest = find_bestub (&desc, (grub_uint8_t *)ub_array, desc.vdev_phys_sector);
      if (!ubbest)
	{
	  grub_dprintf ("zfs", "No uberblock found\n");
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}

      grub_memmove (&(desc.current_uberblock), ubbest, sizeof (uberblock_t));
      if (original)
	grub_memmove (&(data->current_uberblock), ubbest, sizeof (uberblock_t));

check_label:
      err = check_pool_label (data, &desc, inserted, original);
      if (err || !*inserted)
	{
          grub_dprintf("zfs", "check_pool_label of dev=`%s' failed: %d\n",
                       desc.dev->disk->name, err);
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}

      if (original && !dev_ub)
        {
          dev_ub = grub_malloc (sizeof (struct zfs_dev_ublock));
          if (dev_ub)
            {
              dev_ub->dev_name = grub_strdup (data->dev_name);
              dev_ub->dev_id = dev->disk->id;
              dev_ub->pool_id = data->guid;
              dev_ub->vdev_phys_sector = desc.vdev_phys_sector;
              grub_memmove (&(dev_ub->current_uberblock), ubbest, sizeof (uberblock_t));
              if (zfs_dev_ublock_list)
                dev_ub->next = zfs_dev_ublock_list;
              else
                dev_ub->next = NULL;
              zfs_dev_ublock_list = dev_ub;
            }
        }

      if (original && data->n_devices_attached > 0 &&
          data->devices_attached[0].type == DEVICE_MIRROR &&
          find_better_vdev (data, &better_found) == GRUB_ERR_NONE &&
          better_found != 0)
       {
         grub_free(ub_array);
         grub_printf("The %s device is too old and should not be trusted as part of this zpool\n",
                     data->device_original->dev->disk->name);
         return grub_error(GRUB_ERR_BAD_FS, "Better VDEV found for this pool");
       }

      grub_free (ub_array);
      return GRUB_ERR_NONE;
    }

  if (original)
    {
      dev_notzfs = grub_malloc (sizeof (struct zfs_dev_notzfs));
      if (dev_notzfs)
        {
          dev_notzfs->dev_name = grub_strdup (data->dev_name);
          dev_notzfs->dev_id = dev->disk->id;
          if (zfs_dev_notzfs_list)
            dev_notzfs->next = zfs_dev_notzfs_list;
          else
            dev_notzfs->next = NULL;
          zfs_dev_notzfs_list = dev_notzfs;
        }
    } 

  grub_free (ub_array);

  return grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid label");
}

struct scan_devices_ctx {
	struct grub_zfs_data *data;
	grub_uint64_t id;
	grub_device_t dev_found;
};

static int
scan_devices_iter(const char *name, void *hook_data)
{
	struct scan_devices_ctx *ctx = hook_data;
	grub_device_t dev;
	grub_err_t err;
	int inserted;

	grub_dprintf("zfs", "scan_devices: %s\n", name);

	dev = grub_device_open(name);
	if (!dev)
		return 0;
	if (!dev->disk) {
		grub_device_close(dev);
		return 0;
	}
	err = scan_disk(dev, ctx->data, 0, &inserted);
	if (err == GRUB_ERR_BAD_FS) {
		grub_device_close(dev);
		grub_errno = GRUB_ERR_NONE;
		return 0;
	}
	if (err) {
		grub_device_close(dev);
		grub_print_error();
		return 0;
	}

	if (!inserted)
		grub_device_close (dev);

	ctx->dev_found = dev;
	return 1;
}

static grub_err_t
scan_devices (struct grub_zfs_data *data, grub_uint64_t id)
{
	struct scan_devices_ctx ctx;

	ctx.data = data;
	ctx.id = id;
	ctx.dev_found = NULL;

	grub_device_iterate (scan_devices_iter, (void *) &ctx);
	if (!ctx.dev_found)
		return grub_error (GRUB_ERR_BAD_FS,
		    "couldn't find device 0x%" PRIxGRUB_UINT64_T, id);
	return GRUB_ERR_NONE;
}

/* x**y.  */
static grub_uint8_t powx[255 * 2];
/* Such an s that x**s = y */
static int powx_inv[256];
static const grub_uint8_t poly = 0x1d;

/* perform the operation a ^= b * (x ** (known_idx * recovery_pow) ) */
static inline void
xor_out (grub_uint8_t *a, const grub_uint8_t *b, grub_size_t s,
	 unsigned known_idx, unsigned recovery_pow)
{
  unsigned add;

  /* Simple xor.  */
  if (known_idx == 0 || recovery_pow == 0)
    {
      grub_crypto_xor (a, a, b, s);
      return;
    }
  add = (known_idx * recovery_pow) % 255;
  for (;s--; b++, a++)
    if (*b)
      *a ^= powx[powx_inv[*b] + add];
}

static inline grub_uint8_t
gf_mul (grub_uint8_t a, grub_uint8_t b)
{
  if (a == 0 || b == 0)
    return 0;
  return powx[powx_inv[a] + powx_inv[b]];
}

#define	MAX_NBUFS	4

static inline grub_err_t
recovery (grub_uint8_t *bufs[4], grub_size_t s, const int nbufs,
	  const unsigned *powers,
	  const unsigned *idx)
{
  grub_dprintf ("zfs", "recovering %u buffers\n", nbufs);
  /* Now we have */
  /* b_i = sum (r_j* (x ** (powers[i] * idx[j])))*/
  /* Let's invert the matrix in question. */
  switch (nbufs)
    {
      /* Easy: r_0 = bufs[0] / (x << (powers[i] * idx[j])).  */
    case 1:
      {
	int add;
	grub_uint8_t *a;
	if (powers[0] == 0 || idx[0] == 0)
	  return GRUB_ERR_NONE;
	add = 255 - ((powers[0] * idx[0]) % 255);
	for (a = bufs[0]; s--; a++)
	  if (*a)
	    *a = powx[powx_inv[*a] + add];
	return GRUB_ERR_NONE;
      }
      /* Case 2x2: Let's use the determinant formula.  */
    case 2:
      {
	grub_uint8_t det, det_inv;
	grub_uint8_t matrixinv[2][2];
	unsigned i;
	/* The determinant is: */
	det = (powx[(powers[0] * idx[0] + powers[1] * idx[1]) % 255]
	       ^ powx[(powers[0] * idx[1] + powers[1] * idx[0]) % 255]);
	if (det == 0)
	  return grub_error (GRUB_ERR_BAD_FS, "singular recovery matrix");
	det_inv = powx[255 - powx_inv[det]];
	matrixinv[0][0] = gf_mul (powx[(powers[1] * idx[1]) % 255], det_inv);
	matrixinv[1][1] = gf_mul (powx[(powers[0] * idx[0]) % 255], det_inv);
	matrixinv[0][1] = gf_mul (powx[(powers[0] * idx[1]) % 255], det_inv);
	matrixinv[1][0] = gf_mul (powx[(powers[1] * idx[0]) % 255], det_inv);
	for (i = 0; i < s; i++)
	  {
	    grub_uint8_t b0, b1;
	    b0 = bufs[0][i];
	    b1 = bufs[1][i];

	    bufs[0][i] = (gf_mul (b0, matrixinv[0][0])
			  ^ gf_mul (b1, matrixinv[0][1]));
	    bufs[1][i] = (gf_mul (b0, matrixinv[1][0])
			  ^ gf_mul (b1, matrixinv[1][1]));
	  }
	return GRUB_ERR_NONE;
      }
      /* Otherwise use Gauss.  */
    case 3:
      {
	grub_uint8_t matrix1[MAX_NBUFS][MAX_NBUFS], matrix2[MAX_NBUFS][MAX_NBUFS];
	int i, j, k;

	for (i = 0; i < nbufs; i++)
	  for (j = 0; j < nbufs; j++)
	    matrix1[i][j] = powx[(powers[i] * idx[j]) % 255];
	for (i = 0; i < nbufs; i++)
	  for (j = 0; j < nbufs; j++)
	    matrix2[i][j] = 0;
	for (i = 0; i < nbufs; i++)
	    matrix2[i][i] = 1;

	for (i = 0; i < nbufs; i++)
	  {
	    grub_uint8_t mul;
	    for (j = i; j < nbufs; j++)	    
	      if (matrix1[i][j])
		break;
	    if (j == nbufs)
	      return grub_error (GRUB_ERR_BAD_FS, "singular recovery matrix");
	    if (j != i)
	      {
		int xchng;
		xchng = j;
		for (j = 0; j < nbufs; j++)
		  {
		    grub_uint8_t t;
		    t = matrix1[xchng][j];
		    matrix1[xchng][j] = matrix1[i][j];
		    matrix1[i][j] = t;
		  }
		for (j = 0; j < nbufs; j++)
		  {
		    grub_uint8_t t;
		    t = matrix2[xchng][j];
		    matrix2[xchng][j] = matrix2[i][j];
		    matrix2[i][j] = t;
		  }
	      }
	    mul = powx[255 - powx_inv[matrix1[i][i]]];
	    for (j = 0; j < nbufs; j++)
	      matrix1[i][j] = gf_mul (matrix1[i][j], mul);
	    for (j = 0; j < nbufs; j++)
	      matrix2[i][j] = gf_mul (matrix2[i][j], mul);
	    for (j = i + 1; j < nbufs; j++)
	      {
		mul = matrix1[j][i];
		for (k = 0; k < nbufs; k++)
		  matrix1[j][k] ^= gf_mul (matrix1[i][k], mul);
		for (k = 0; k < nbufs; k++)
		  matrix2[j][k] ^= gf_mul (matrix2[i][k], mul);
	      }
	  }
	for (i = nbufs - 1; i >= 0; i--)
	  {
	    for (j = 0; j < i; j++)
	      {
		grub_uint8_t mul;
		mul = matrix1[j][i];
		for (k = 0; k < nbufs; k++)
		  matrix1[j][k] ^= gf_mul (matrix1[i][k], mul);
		for (k = 0; k < nbufs; k++)
		  matrix2[j][k] ^= gf_mul (matrix2[i][k], mul);
	      }
	  }

	for (i = 0; i < (int) s; i++)
	  {
	    grub_uint8_t b[MAX_NBUFS];
	    for (j = 0; j < nbufs; j++)
	      b[j] = bufs[j][i];
	    for (j = 0; j < nbufs; j++)
	      {
		bufs[j][i] = 0;
		for (k = 0; k < nbufs; k++)
		  bufs[j][i] ^= gf_mul (matrix2[j][k], b[k]);
	      }
	  }
	return GRUB_ERR_NONE;
      }
      default:
	return grub_error (GRUB_ERR_BUG, N_("too big matrix"));
    }      
}

/*
 *  vdev_raidz_map_get() is hacked from vdev_raidz_map_alloc() in
 *  usr/src/uts/common/fs/zfs/vdev_raidz.c.  If that routine changes,
 *  this might also need changing.
 */

#ifndef MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#ifndef roundup
#define	roundup(x, y)	(grub_divmod64 ( (x)+((y)-1), (y), NULL) *(y))
#endif
#ifndef offsetof
#define	offsetof(s, m)	((grub_size_t)(&(((s *)0)->m)))
#endif

static raidz_map_t *
vdev_raidz_map_get(grub_uint64_t size, grub_uint64_t offset,
		   grub_uint64_t unit_shift, grub_uint64_t dcols,
		   grub_uint64_t nparity)
{
  raidz_map_t *rm;
  grub_uint64_t b = offset >> unit_shift;
  grub_uint64_t s = size >> unit_shift;
  grub_uint64_t f, o, q, r, c, bc, col, acols, scols, coff, devidx, asize, tot;

  o = grub_divmod64(b, dcols, NULL) << unit_shift;
  (void) grub_divmod64(b, dcols, &f);
  q = grub_divmod64(s, dcols - nparity, NULL);
  r = s - q * (dcols - nparity);
  bc = (r == 0 ? 0 : r + nparity);
  tot = s + nparity * (q + (r == 0 ? 0 : 1));

  if (q == 0)
    {
      acols = bc;
      scols = MIN(dcols, roundup(bc, nparity + 1));
    }
  else
    {
      acols = dcols;
      scols = dcols;
    }

  rm = grub_malloc(offsetof(raidz_map_t, rm_col[scols]));

  if (rm == NULL)
    {
      return NULL;
    }

  rm->rm_cols = acols;
  rm->rm_scols = scols;
  rm->rm_bigcols = bc;
  rm->rm_skipstart = bc;
  rm->rm_missingdata = 0;
  rm->rm_missingparity = 0;
  rm->rm_firstdatacol = nparity;
  rm->rm_datacopy = NULL;
  rm->rm_reports = 0;
  rm->rm_freed = 0;
  rm->rm_ecksuminjected = 0;

  asize = 0;

  for (c = 0; c < scols; c++)
    {
      col = f + c;
      coff = o;
      if (col >= dcols)
	{
	  col -= dcols;
	  coff += 1ULL << unit_shift;
	}
      rm->rm_col[c].rc_devidx = col;
      rm->rm_col[c].rc_offset = coff;
      rm->rm_col[c].rc_data = NULL;
      rm->rm_col[c].rc_gdata = NULL;
      rm->rm_col[c].rc_error = 0;
      rm->rm_col[c].rc_tried = 0;
      rm->rm_col[c].rc_skipped = 0;

      if (c >= acols)
	rm->rm_col[c].rc_size = 0;
      else if (c < bc)
	rm->rm_col[c].rc_size = (q + 1) << unit_shift;
      else
	rm->rm_col[c].rc_size = q << unit_shift;

      asize += rm->rm_col[c].rc_size;
    }

  rm->rm_asize = roundup(asize, (nparity + 1) << unit_shift);
  rm->rm_nskip = roundup(tot, nparity + 1) - tot;

  /*
   * If all data stored spans all columns, there's a danger that parity
   * will always be on the same device and, since parity isn't read
   * during normal operation, that that device's I/O bandwidth won't be
   * used effectively. We therefore switch the parity every 1MB.
   *
   * ... at least that was, ostensibly, the theory. As a practical
   * matter unless we juggle the parity between all devices evenly, we
   * won't see any benefit. Further, occasional writes that aren't a
   * multiple of the LCM of the number of children and the minimum
   * stripe width are sufficient to avoid pessimal behavior.
   * Unfortunately, this decision created an implicit on-disk format
   * requirement that we need to support for all eternity, but only
   * for single-parity RAID-Z.
   *
   * If we intend to skip a sector in the zeroth column for padding
   * we must make sure to note this swap. We will never intend to
   * skip the first column since at least one data and one parity
   * column must appear in each row.
   */

  if (rm->rm_firstdatacol == 1 && (offset & (1ULL << 20)))
    {
       devidx = rm->rm_col[0].rc_devidx;
       o = rm->rm_col[0].rc_offset;
       rm->rm_col[0].rc_devidx = rm->rm_col[1].rc_devidx;
       rm->rm_col[0].rc_offset = rm->rm_col[1].rc_offset;
       rm->rm_col[1].rc_devidx = devidx;
       rm->rm_col[1].rc_offset = o;

       if (rm->rm_skipstart == 0)
	 rm->rm_skipstart = 1;
    }

  return (rm);
}

static grub_err_t
read_device (grub_uint64_t offset, struct grub_zfs_device_desc *desc,
	     grub_size_t len, void *buf)
{
  switch (desc->type)
    {
    case DEVICE_LEAF:
      {
	grub_uint64_t sector;
	sector = DVA_OFFSET_TO_PHYS_SECTOR (offset);
	grub_dprintf("zfs", "read_device: offset %llx sector %llx\n",
		   (unsigned long long) offset,
		   (unsigned long long) sector);
	if (!desc->dev)
	  {
	    return grub_error (GRUB_ERR_BAD_FS,
			       N_("couldn't find a necessary member device "
				  "of multi-device filesystem"));
	  }
	if (desc->dev_state == DEVICE_ERROR)
	  {
	    return grub_error (GRUB_ERR_BAD_DEVICE, "dev state is NOT OK.\n");
	  }
	/* read in a data block */
	return grub_disk_read (desc->dev->disk, sector, 0, len, buf);
      }
    case DEVICE_MIRROR:
      {
	grub_err_t err = GRUB_ERR_NONE;
	unsigned i;
	if (desc->n_children <= 0)
	  return grub_error (GRUB_ERR_BAD_FS,
			     "non-positive number of mirror children");
	for (i = 0; i < desc->n_children; i++)
	  {
	    err = read_device (offset, &desc->children[i],
			       len, buf);
	    if (!err)
	      break;
	    grub_errno = GRUB_ERR_NONE;
	  }
	return (grub_errno = err);
      }
    case DEVICE_RAIDZ:
      {
	raidz_map_t *rzm;
	raidz_col_t *cols;
	unsigned i;
	grub_err_t err;

	if (desc->nparity < 1 || desc->nparity > 3)
	  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
			     "raidz%d is not supported", desc->nparity);

	if (desc->n_children <= desc->nparity || desc->n_children < 1)
	  return grub_error(GRUB_ERR_BAD_FS,
			    "too little devices for given parity");

	rzm = vdev_raidz_map_get(len, offset, desc->ashift, desc->n_children,
				 desc->nparity);
	if (rzm == NULL)
	  return grub_errno;

	grub_dprintf("zfs", "read_device: cols = %" PRIuGRUB_UINT64_T
		     ", firstdatacol = %" PRIuGRUB_UINT64_T "\n",
		     rzm->rm_cols, rzm->rm_firstdatacol);

	for (i = 0, cols = &rzm->rm_col[0]; i < rzm->rm_cols; i++, cols++)
	  {
	    grub_dprintf("zfs", "%" PRIuGRUB_UINT64_T ":%" PRIxGRUB_UINT64_T
			 ":%" PRIxGRUB_UINT64_T "\n", cols->rc_devidx,
			 cols->rc_offset, cols->rc_size);
	    if (i == 0) /* skip parity for now */
	      continue;

	    err = read_device (cols->rc_offset,
			       &desc->children[cols->rc_devidx],
			       cols->rc_size, buf);
	    if (err)
	      return err;

	    buf = (char *) buf + cols->rc_size;
	    len -= cols->rc_size;
	  }
	grub_free(rzm);
	grub_dprintf("zfs", "read_device: len = %" PRIdGRUB_SSIZE "\n", len);

#if 0
	unsigned c = 0;
	grub_uint64_t high;
	grub_uint64_t devn;
	grub_uint64_t m;
	grub_uint32_t s, orig_s;
	void *orig_buf = buf;
	grub_size_t orig_len = len;
	grub_uint8_t *recovery_buf[4];
	grub_size_t recovery_len[4];
	unsigned recovery_idx[4];
	unsigned failed_devices = 0;
	int idx, orig_idx;

	orig_s = (((len + (1 << desc->ashift) - 1) >> desc->ashift)
		  + (desc->n_children - desc->nparity) - 1);
	s = orig_s;

	high = grub_divmod64 ((offset >> desc->ashift),
			      desc->n_children, &m);
	if (desc->nparity == 2)
	  c = 2;
	if (desc->nparity == 3)
	  c = 3;
	if (((len + (1 << desc->ashift) - 1) >> desc->ashift)
	    >= (desc->n_children - desc->nparity))
	  idx = (desc->n_children - desc->nparity - 1);
	else
	  idx = ((len + (1 << desc->ashift) - 1) >> desc->ashift) - 1;
	orig_idx = idx;
	while (len > 0)
	  {
	    grub_size_t csize;
	    grub_uint32_t bsize;
	    bsize = s / (desc->n_children - desc->nparity);

	    if (desc->nparity == 1
		&& ((offset >> (desc->ashift + 20 - desc->max_children_ashift))
		    & 1) == c)
	      c++;

	    high = grub_divmod64 ((offset >> desc->ashift) + c,
				  desc->n_children, &devn);
	    csize = bsize << desc->ashift;
	    if (csize > len)
	      csize = len;

	    grub_dprintf ("zfs", "RAIDZ mapping 0x%" PRIxGRUB_UINT64_T
			  "+%u (%" PRIxGRUB_SIZE ", %" PRIxGRUB_UINT32_T
			  ") -> (0x%" PRIxGRUB_UINT64_T ", 0x%"
			  PRIxGRUB_UINT64_T ")\n",
			  offset >> desc->ashift, c, len, bsize, high,
			  devn);

	    err = read_device ((high << desc->ashift)
			       | (offset & ((1 << desc->ashift) - 1)),
			       &desc->children[devn],
			       csize, buf);
	    if (err && failed_devices < desc->nparity)
	      {
		recovery_buf[failed_devices] = buf;
		recovery_len[failed_devices] = csize;
		recovery_idx[failed_devices] = idx;
		failed_devices++;
		grub_errno = err = 0;
	      }
	    if (err)
	      return err;

	    c++;
	    idx--;
	    s--;
	    buf = (char *) buf + csize;
	    len -= csize;
	  }
	if (failed_devices)
	  {
	    unsigned redundancy_pow[4];
	    unsigned cur_redundancy_pow = 0;
	    unsigned n_redundancy = 0;
	    unsigned i, j;
	    grub_err_t err;

	    /* Compute mul. x**s has a period of 255.  */
	    if (powx[0] == 0)
	      {
		grub_uint8_t cur = 1;
		for (i = 0; i < 255; i++)
		  {
		    powx[i] = cur;
		    powx[i + 255] = cur;
		    powx_inv[cur] = i;
		    if (cur & 0x80)
		      cur = (cur << 1) ^ poly;
		    else
		      cur <<= 1;
		  }
	      }

	    /* Read redundancy data.  */
	    for (n_redundancy = 0, cur_redundancy_pow = 0;
		 n_redundancy < failed_devices;
		 cur_redundancy_pow++)
	      {
		high = grub_divmod64 ((offset >> desc->ashift)
				      + cur_redundancy_pow
				      + ((desc->nparity == 1)
					 && ((offset >> (desc->ashift + 20
							 - desc->max_children_ashift))
					     & 1)),
				      desc->n_children, &devn);
		err = read_device ((high << desc->ashift)
				   | (offset & ((1 << desc->ashift) - 1)),
				   &desc->children[devn],
				   recovery_len[n_redundancy],
				   recovery_buf[n_redundancy]);
		/* Ignore error if we may still have enough devices.  */
		if (err && n_redundancy + desc->nparity - cur_redundancy_pow - 1
		    >= failed_devices)
		  {
		    grub_errno = GRUB_ERR_NONE;
		    continue;
		  }
		if (err)
		  return err;
		redundancy_pow[n_redundancy] = cur_redundancy_pow;
		n_redundancy++;
	      }
	    /* Now xor-our the parts we already know.  */
	    buf = orig_buf;
	    len = orig_len;
	    s = orig_s;
	    idx = orig_idx;

	    while (len > 0)
	      {
		grub_size_t csize;
		csize = ((s / (desc->n_children - desc->nparity))
			 << desc->ashift);
		if (csize > len)
		  csize = len;

		for (j = 0; j < failed_devices; j++)
		  if (buf == recovery_buf[j])
		    break;

		if (j == failed_devices)
		  for (j = 0; j < failed_devices; j++)
		    xor_out (recovery_buf[j], buf,
			     csize < recovery_len[j] ? csize : recovery_len[j],
			     idx, redundancy_pow[j]);

		s--;
		buf = (char *) buf + csize;
		len -= csize;
		idx--;
	      }
	    for (i = 0; i < failed_devices 
		   && recovery_len[i] == recovery_len[0];
		 i++);
	    /* Since the chunks have variable length handle the last block
	       separately.  */
	    if (i != failed_devices)
	      {
		grub_uint8_t *tmp_recovery_buf[4];
		for (j = 0; j < i; j++)
		  tmp_recovery_buf[j] = recovery_buf[j] + recovery_len[failed_devices - 1];
		err = recovery (tmp_recovery_buf, recovery_len[0] - recovery_len[failed_devices - 1], i, redundancy_pow,
				recovery_idx);
		if (err)
		  return err;
	      }
	    err = recovery (recovery_buf, recovery_len[failed_devices - 1],
			    failed_devices, redundancy_pow, recovery_idx);
	    if (err)
	      return err;
	  }
#endif
	return GRUB_ERR_NONE;
      }
    }
  return grub_error (GRUB_ERR_BAD_FS, "unsupported device type");
}

static grub_err_t
read_dva (const dva_t *dva,
	  grub_zfs_endian_t endian, struct grub_zfs_data *data,
	  void *buf, grub_size_t len)
{
  grub_uint64_t offset;
  unsigned i;
  grub_err_t err = 0;
  int try = 0;
  offset = dva_get_offset (dva, endian);

  for (try = 0; try < 2; try++)
    {
      for (i = 0; i < data->n_devices_attached; i++)
	if (data->devices_attached[i].id == DVA_GET_VDEV (dva))
	  {
	    err = read_device (offset, &data->devices_attached[i], len, buf);
	    if (!err)
	      return GRUB_ERR_NONE;
	    break;
	  }
      if (try == 1)
	break;
      err = scan_devices (data, DVA_GET_VDEV (dva));
      if (err)
	return err;
    }
  if (!err)
    return grub_error (GRUB_ERR_BAD_FS, "unknown device %d",
		       (int) DVA_GET_VDEV (dva));
  return err;
}

/*
 * Read a block of data based on the gang block address dva,
 * and put its data in buf.
 */
static grub_err_t
zio_read_gang_data (blkptr_t * bp, grub_zfs_endian_t endian, void *buf, 
	       struct grub_zfs_data *data)
{
  int i;

  /* pick a good dva from the block pointer */
  for (i = 0; i < BP_GET_NDVAS(bp); i++)
    {
      if (zio_read_common(bp, &bp->blk_dva[i], endian, buf, data) == GRUB_ERR_NONE)
	return GRUB_ERR_NONE;
    }
  return grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid DVA");
}

/*
 * Read gang block header, verify its checksum, loop through all gang blocks
 * to collect its data based on the gang block address dva and put it in buf.
 *
 */
static grub_err_t
zio_read_gang (blkptr_t * bp, grub_zfs_endian_t endian, dva_t * dva, void *buf,
	       struct grub_zfs_data *data)
{
  zio_gbh_phys_t *zio_gb;
  unsigned i;
  grub_err_t err;
  zio_cksum_t zc;

  grub_memset (&zc, 0, sizeof (zc));

  zio_gb = grub_malloc (SPA_GANGBLOCKSIZE);
  if (!zio_gb)
    return grub_errno;
  grub_dprintf ("zfs", endian == GRUB_ZFS_LITTLE_ENDIAN ? "little-endian gang\n"
		:"big-endian gang\n");

  err = read_dva (dva, endian, data, zio_gb, SPA_GANGBLOCKSIZE);
  if (err)
    {
      grub_free (zio_gb);
      return err;
    }

  /* XXX */
  /* self checksuming the gang block header */
  ZIO_SET_CHECKSUM (&zc, DVA_GET_VDEV (dva),
		    dva_get_offset (dva, endian), bp->blk_birth, 0);
  err = zio_checksum_verify (zc, ZIO_CHECKSUM_GANG_HEADER, endian,
			     (char *) zio_gb, SPA_GANGBLOCKSIZE);
  if (err)
    {
      grub_free (zio_gb);
      return err;
    }

  endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;

  for (i = 0; i < SPA_GBH_NBLKPTRS; i++)
    {
      if (zio_gb->zg_blkptr[i].blk_birth == 0)
	continue;

      err = zio_read_gang_data (&zio_gb->zg_blkptr[i], endian, buf, data);
      if (err)
	{
	  grub_free (zio_gb);
	  return err;
	}
      buf = (char *) buf + get_psize (&zio_gb->zg_blkptr[i], endian);
    }
  grub_free (zio_gb);
  return GRUB_ERR_NONE;
}

/*
 * Read in a block of raw data to buf.
 */
static grub_err_t
zio_read_common (blkptr_t * bp, dva_t *dva, grub_zfs_endian_t endian,
		void *buf, struct grub_zfs_data *data)
{
  int psize;
  grub_err_t err = GRUB_ERR_NONE;

  psize = get_psize (bp, endian);

  if (dva->dva_word[0] == 0 && dva->dva_word[1] == 0)
    return grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid DVA");

  if ((grub_zfs_to_cpu64 (dva->dva_word[1], endian)>>63) & 1)
    err = zio_read_gang (bp, endian, dva, buf, data);
  else
    err = read_dva (dva, endian, data, buf, psize);

  return err;

}

/*
 * Loop through DVAs to read in a block of raw data to buf and verify 
 * the checksum.
 */
static grub_err_t
zio_read_data (blkptr_t * bp, grub_zfs_endian_t endian, void *buf, 
	       struct grub_zfs_data *data)
{
  int i, psize;
  grub_err_t err = GRUB_ERR_NONE;
  zio_cksum_t zc = bp->blk_cksum;
  grub_uint32_t checksum;

  psize = get_psize (bp, endian);
  checksum = BP_GET_CHECKSUM(bp, endian);

  /* pick a good dva from the block pointer */
  for (i = 0; i < BP_GET_NDVAS(bp); i++)
    {
      if (zio_read_common(bp, &bp->blk_dva[i], endian, buf, data) != GRUB_ERR_NONE)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      err = zio_checksum_verify (zc, checksum, endian, buf, psize);
      if (err)
	{
	  grub_dprintf ("zfs", "incorrect checksum\n");
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}
      /* if no errors, return from here */
      return GRUB_ERR_NONE;
    }

  err = grub_error (GRUB_ERR_BAD_FS, "couldn't find a valid DVA");
  grub_errno = err;

  return err;
}

/*
 * buf must be at least BPE_GET_PSIZE(bp) bytes long (which will never be
 * more than BPE_PAYLOAD_SIZE bytes).
 */
static grub_err_t
decode_embedded_bp_compressed(const blkptr_t *bp, grub_zfs_endian_t endian,
    void *buf)
{
       grub_size_t psize, i;
       grub_uint8_t *buf8 = buf;
       grub_uint64_t w = 0;
       const grub_uint64_t *bp64 = (const grub_uint64_t *)bp;

       psize = BPE_GET_PSIZE(bp, endian);

       /*
        * Decode the words of the block pointer into the byte array.
        * Low bits of first word are the first byte (little endian).
        */
       for (i = 0; i < psize; i++) {
               if (i % sizeof (w) == 0) {
                       /* beginning of a word */
                       w = grub_zfs_to_cpu64(*bp64, endian);
                       bp64++;
                       if (!BPE_IS_PAYLOADWORD(bp, bp64))
                               bp64++;
               }
               buf8[i] = BF64_GET(w, (i % sizeof (w)) * NBBY, NBBY);
       }
       return GRUB_ERR_NONE;
}

/*
 * Read in a block of data, verify its checksum, decompress if needed,
 * and put the uncompressed data in buf.
 */
static grub_err_t
zio_read (blkptr_t *bp, grub_zfs_endian_t endian, void **buf, 
	  grub_size_t *size, struct grub_zfs_data *data)
{
  grub_size_t lsize, psize;
  unsigned int comp, encrypted;
  char *compbuf = NULL;
  grub_err_t err;
  zio_cksum_t zc = bp->blk_cksum;
  grub_uint32_t checksum;

  *buf = NULL;

  comp = BP_GET_COMPRESS(bp, endian);
  encrypted = ((grub_zfs_to_cpu64((bp)->blk_prop, endian) >> 60) & 3);

  grub_dprintf("zfs", "zio_read compress %d\n", (unsigned int) comp);
  if (BP_IS_EMBEDDED(bp, endian)) {
	if(BPE_GET_ETYPE(bp, endian) != BP_EMBEDDED_TYPE_DATA) {
		return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
			"unsupported embedded BP (type=%u)\n",
			(int) BPE_GET_ETYPE(bp, endian));
	}
	lsize = BPE_GET_LSIZE(bp, endian);
	psize = BPE_GET_PSIZE(bp, endian);
  } else {
	lsize = BP_GET_LSIZE(bp, endian);
	psize = BP_GET_PSIZE(bp, endian);
  }

  if (comp >= ZIO_COMPRESS_FUNCTIONS)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "compression algorithm %u not supported\n", (unsigned int) comp);

  if (comp != ZIO_COMPRESS_OFF && decomp_table[comp].decomp_func == NULL)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "compression algorithm %s not supported\n", decomp_table[comp].name);

  if (comp != ZIO_COMPRESS_OFF)
    {
      /* It's not really necessary to align to 16, just for safety.  */
      compbuf = grub_malloc (ALIGN_UP (psize, 16));
      if (! compbuf)
	return grub_errno;
    }
  else
    {
      compbuf = *buf = grub_malloc (lsize);
	if (! compbuf)
	  return grub_errno;
    }

  if (size)
     *size = lsize;

  grub_dprintf ("zfs", "endian = %d\n", endian);
  if (BP_IS_EMBEDDED(bp, endian)) {
    err = decode_embedded_bp_compressed(bp, endian, compbuf);
  } else {
    err = zio_read_data (bp, endian, compbuf, data);
    grub_memset (compbuf, 0, ALIGN_UP (psize, 16) - psize);
  }

  if (err)
    {
      grub_free (compbuf);
      *buf = NULL;
      return err;
    }

  /* Embedded data has no checkum field... */
  if (!BP_IS_EMBEDDED(bp, endian)) {
    checksum = BP_GET_CHECKSUM(bp, endian);
    err = zio_checksum_verify (zc, checksum, endian,
			     compbuf, psize);
    if (err)
      {
        grub_dprintf ("zfs", "incorrect checksum\n");
        grub_free (compbuf);
        *buf = NULL;
        return err;
      }
  }

  if (encrypted)
    {
      if (!grub_zfs_decrypt)
	err = grub_error (GRUB_ERR_BAD_FS, 
			  N_("module `%s' isn't loaded"),
			  "zfscrypt");
      else
	{
	  unsigned i, besti = 0;
	  grub_uint64_t bestval = 0;
	  for (i = 0; i < data->subvol.nkeys; i++)
	    if (data->subvol.keyring[i].txg <= grub_zfs_to_cpu64 (bp->blk_birth,
								  endian)
		&& data->subvol.keyring[i].txg > bestval)
	      {
		besti = i;
		bestval = data->subvol.keyring[i].txg;
	      }
	  if (bestval == 0)
	    {
	      grub_free (compbuf);
	      *buf = NULL;
	      grub_dprintf ("zfs", "no key for txg %" PRIxGRUB_UINT64_T "\n",
			    grub_zfs_to_cpu64 (bp->blk_birth,
					       endian));
	      return grub_error (GRUB_ERR_BAD_FS, "no key found in keychain");
	    }
	  grub_dprintf ("zfs", "using key %u (%" PRIxGRUB_UINT64_T 
			", %p) for txg %" PRIxGRUB_UINT64_T "\n",
			besti, data->subvol.keyring[besti].txg,
			data->subvol.keyring[besti].cipher,
			grub_zfs_to_cpu64 (bp->blk_birth,
					   endian));
	  err = grub_zfs_decrypt (data->subvol.keyring[besti].cipher,
				  data->subvol.keyring[besti].algo,
				  &(bp)->blk_dva[encrypted],
				  compbuf, psize, zc.zc_mac,
				  endian);
	}
      if (err)
	{
	  grub_free (compbuf);
	  *buf = NULL;
	  return err;
	}
    }

  if (comp != ZIO_COMPRESS_OFF)
    {
      *buf = grub_malloc (lsize);
      if (!*buf)
	{
	  grub_free (compbuf);
	  return grub_errno;
	}

      err = decomp_table[comp].decomp_func (compbuf, *buf, psize, lsize);
      grub_free (compbuf);
      if (err)
	{
	  grub_free (*buf);
	  *buf = NULL;
	  return err;
	}
    }

  return GRUB_ERR_NONE;
}

/*
 * Get the block from a block id.
 * push the block onto the stack.
 *
 */
static grub_err_t
dmu_read (dnode_end_t * dn, grub_uint64_t blkid, void **buf, 
	  grub_zfs_endian_t *endian_out, struct grub_zfs_data *data)
{
  int level;
  grub_off_t idx;
  blkptr_t *bp_array = dn->dn.dn_blkptr;
  int epbs = dn->dn.dn_indblkshift - SPA_BLKPTRSHIFT;
  blkptr_t *bp;
  void *tmpbuf = 0;
  grub_zfs_endian_t endian;
  grub_err_t err = GRUB_ERR_NONE;

  endian = dn->endian;
  for (level = dn->dn.dn_nlevels - 1; level >= 0; level--)
    {
      grub_dprintf ("zfs", "endian = %d\n", endian);
      idx = (blkid >> (epbs * level)) & ((1 << epbs) - 1);
      bp = &bp_array[idx];
      if (BP_IS_HOLE (bp, endian))
	{
	  grub_size_t size = grub_zfs_to_cpu16 (dn->dn.dn_datablkszsec, 
						dn->endian) 
	    << SPA_MINBLOCKSHIFT;
	  *buf = grub_malloc (size);
	  if (!*buf)
	    {
	      err = grub_errno;
	      break;
	    }
	  grub_memset (*buf, 0, size);
	  endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;
	  break;
	}
      if (level == 0)
	{
	  grub_dprintf ("zfs", "endian = %d\n", endian);
	  err = zio_read (bp, endian, buf, 0, data);
	  endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;
	  break;
	}
      grub_dprintf ("zfs", "endian = %d\n", endian);
      err = zio_read (bp, endian, &tmpbuf, 0, data);
      endian = (grub_zfs_to_cpu64 (bp->blk_prop, endian) >> 63) & 1;
      if (err)
	break;
      if (bp_array != dn->dn.dn_blkptr)
        grub_free (bp_array);
      bp_array = tmpbuf;
    }
  if (bp_array != dn->dn.dn_blkptr)
    grub_free (bp_array);
  if (endian_out)
    *endian_out = endian;

  return err;
}

/*
 * mzap_lookup: Looks up property described by "name" and returns the value
 * in "value".
 */
static grub_err_t
mzap_lookup (mzap_phys_t * zapobj, grub_zfs_endian_t endian,
	     int objsize, const char *name, grub_uint64_t * value,
	     int case_insensitive)
{
  int i, chunks;
  mzap_ent_phys_t *mzap_ent = zapobj->mz_chunk;

  chunks = objsize / MZAP_ENT_LEN - 1;
  for (i = 0; i < chunks; i++)
    {
      if (case_insensitive ? (grub_strcasecmp (mzap_ent[i].mze_name, name) == 0)
	  : (grub_strcmp (mzap_ent[i].mze_name, name) == 0))
	{
	  *value = grub_zfs_to_cpu64 (mzap_ent[i].mze_value, endian);
	  return GRUB_ERR_NONE;
	}
    }

  return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), name);
}

/*
 * mzap_value_search: Looks up value and returns property name.
 */
static grub_err_t
mzap_value_search (mzap_phys_t *zapobj, grub_zfs_endian_t endian,
	     int objsize, char *name, grub_uint64_t *value)
{
  int i, chunks;
  mzap_ent_phys_t *mzap_ent = zapobj->mz_chunk;
  grub_uint64_t mze_val;

  chunks = objsize / MZAP_ENT_LEN - 1;
  for (i = 0; i < chunks; i++)
    {
	mze_val = grub_zfs_to_cpu64 (mzap_ent[i].mze_value, endian);
	if (mze_val == *value)
	  {
	    grub_memcpy (name, mzap_ent[i].mze_name, grub_strlen
			 (mzap_ent[i].mze_name) + 1);
	    return GRUB_ERR_NONE;
	  }
    }

  return grub_error (GRUB_ERR_FILE_NOT_FOUND,
			"mzap_value_search: couldn't find %s", value);
}

static int
mzap_iterate (mzap_phys_t * zapobj, grub_zfs_endian_t endian, int objsize, 
    int (*hook) (const char *name, grub_uint64_t val,
	struct grub_zfs_dir_ctx *ctx),
    struct grub_zfs_dir_ctx *ctx)
{
  int i, chunks;
  mzap_ent_phys_t *mzap_ent = zapobj->mz_chunk;

  chunks = objsize / MZAP_ENT_LEN - 1;
  for (i = 0; i < chunks; i++)
    {
      grub_dprintf ("zfs", "zap: name = %s, value = %llx, cd = %x\n",
		    mzap_ent[i].mze_name, (long long)mzap_ent[i].mze_value,
		    (int)mzap_ent[i].mze_cd);
      if (hook (mzap_ent[i].mze_name, 
		grub_zfs_to_cpu64 (mzap_ent[i].mze_value, endian), ctx))
	return 1;
    }

  return 0;
}

static grub_uint64_t
zap_hash (grub_uint64_t salt, const char *name,
	  int case_insensitive)
{
  static grub_uint64_t table[256];
  const grub_uint8_t *cp;
  grub_uint8_t c;
  grub_uint64_t crc = salt;

  if (table[128] == 0)
    {
      grub_uint64_t *ct;
      int i, j;
      for (i = 0; i < 256; i++)
	{
	  for (ct = table + i, *ct = i, j = 8; j > 0; j--)
	    *ct = (*ct >> 1) ^ (-(*ct & 1) & ZFS_CRC64_POLY);
	}
    }

  if (case_insensitive)
    for (cp = (const grub_uint8_t *) name; (c = *cp) != '\0'; cp++)
      crc = (crc >> 8) ^ table[(crc ^ grub_toupper (c)) & 0xFF];
  else
    for (cp = (const grub_uint8_t *) name; (c = *cp) != '\0'; cp++)
      crc = (crc >> 8) ^ table[(crc ^ c) & 0xFF];

  /*
   * Only use 28 bits, since we need 4 bits in the cookie for the
   * collision differentiator.  We MUST use the high bits, since
   * those are the onces that we first pay attention to when
   * chosing the bucket.
   */
  crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

  return (crc);
}

/*
 * Only to be used on 8-bit arrays.
 * array_len is actual len in bytes (not encoded le_value_length).
 * buf is null-terminated.
 */

static inline int
name_cmp (const char *s1, const char *s2, grub_size_t n,
	  int case_insensitive)
{
  const char *t1 = (const char *) s1;
  const char *t2 = (const char *) s2;

  if (!case_insensitive)
    return grub_memcmp (t1, t2, n);
      
  while (n--)
    {
      if (grub_toupper (*t1) != grub_toupper (*t2))
	  return (int) grub_toupper (*t1) - (int) grub_toupper (*t2);
	  
      t1++;
      t2++;
    }

  return 0;
}

/* XXX */
static int
zap_leaf_array_equal (zap_leaf_phys_t * l, grub_zfs_endian_t endian,
		      int blksft, int chunk, grub_size_t array_len,
		      const char *buf, int case_insensitive)
{
  grub_size_t bseen = 0;

  while (bseen < array_len)
    {
      struct zap_leaf_array *la = &ZAP_LEAF_CHUNK (l, blksft, chunk)->l_array;
      grub_size_t toread = array_len - bseen;

      if (toread > ZAP_LEAF_ARRAY_BYTES)
	toread = ZAP_LEAF_ARRAY_BYTES;

      if (chunk >= ZAP_LEAF_NUMCHUNKS (blksft))
	return 0;

      if (name_cmp ((char *) la->la_array, buf + bseen, toread,
		    case_insensitive) != 0)
	break;
      chunk = grub_zfs_to_cpu16 (la->la_next, endian);
      bseen += toread;
    }
  return (bseen == array_len);
}

/* XXX */
static grub_err_t
zap_leaf_array_get (zap_leaf_phys_t * l, grub_zfs_endian_t endian, int blksft, 
		    int chunk, grub_size_t array_len, char *buf)
{
  grub_size_t bseen = 0;

  while (bseen < array_len)
    {
      struct zap_leaf_array *la = &ZAP_LEAF_CHUNK (l, blksft, chunk)->l_array;
      grub_size_t toread = array_len - bseen;

      if (toread > ZAP_LEAF_ARRAY_BYTES)
	toread = ZAP_LEAF_ARRAY_BYTES;

      if (chunk >= ZAP_LEAF_NUMCHUNKS (blksft))
	/* Don't use grub_error because this error is to be ignored.  */
	return GRUB_ERR_BAD_FS;

      grub_memcpy (buf + bseen,la->la_array,  toread);
      chunk = grub_zfs_to_cpu16 (la->la_next, endian);
      bseen += toread;
    }
  return GRUB_ERR_NONE;
}


/*
 * Given a zap_leaf_phys_t, walk thru the zap leaf chunks to get the
 * value for the property "name".
 *
 */
/* XXX */
static grub_err_t
zap_leaf_lookup (zap_leaf_phys_t * l, grub_zfs_endian_t endian,
		 int blksft, grub_uint64_t h,
		 const char *name, grub_uint64_t * value,
		 int case_insensitive)
{
  grub_uint16_t chunk;
  struct zap_leaf_entry *le;

  /* Verify if this is a valid leaf block */
  if (grub_zfs_to_cpu64 (l->l_hdr.lh_block_type, endian) != ZBT_LEAF)
    return grub_error (GRUB_ERR_BAD_FS, "invalid leaf type");
  if (grub_zfs_to_cpu32 (l->l_hdr.lh_magic, endian) != ZAP_LEAF_MAGIC)
    return grub_error (GRUB_ERR_BAD_FS, "invalid leaf magic");

  for (chunk = grub_zfs_to_cpu16 (l->l_hash[LEAF_HASH (blksft, h, l)], endian);
       chunk != CHAIN_END; chunk = grub_zfs_to_cpu16 (le->le_next, endian))
    {

      if (chunk >= ZAP_LEAF_NUMCHUNKS (blksft))
	return grub_error (GRUB_ERR_BAD_FS, "invalid chunk number");

      le = ZAP_LEAF_ENTRY (l, blksft, chunk);

      /* Verify the chunk entry */
      if (le->le_type != ZAP_CHUNK_ENTRY)
	return grub_error (GRUB_ERR_BAD_FS, "invalid chunk entry");

      if (grub_zfs_to_cpu64 (le->le_hash,endian) != h)
	continue;

      grub_dprintf ("zfs", "fzap: length %d\n", (int) le->le_name_length);

      if (zap_leaf_array_equal (l, endian, blksft, 
				grub_zfs_to_cpu16 (le->le_name_chunk,endian),
				grub_zfs_to_cpu16 (le->le_name_length, endian),
				name, case_insensitive))
	{
	  struct zap_leaf_array *la;

	  if (le->le_int_size != 8 || grub_zfs_to_cpu16 (le->le_value_length,
							 endian) != 1)
	    return grub_error (GRUB_ERR_BAD_FS, "invalid leaf chunk entry");

	  /* get the uint64_t property value */
	  la = &ZAP_LEAF_CHUNK (l, blksft, le->le_value_chunk)->l_array;

	  *value = grub_be_to_cpu64 (la->la_array64);

	  return GRUB_ERR_NONE;
	}
    }

  return grub_error (GRUB_ERR_FILE_NOT_FOUND, N_("file `%s' not found"), name);
}


/* Verify if this is a fat zap header block */
static grub_err_t
zap_verify (zap_phys_t *zap, grub_zfs_endian_t endian)
{
  if (grub_zfs_to_cpu64 (zap->zap_magic, endian) != (grub_uint64_t) ZAP_MAGIC)
    return grub_error (GRUB_ERR_BAD_FS, "bad ZAP magic");

  if (zap->zap_salt == 0)
    return grub_error (GRUB_ERR_BAD_FS, "bad ZAP salt");

  return GRUB_ERR_NONE;
}

/*
 * Fat ZAP lookup
 *
 */
/* XXX */
static grub_err_t
fzap_lookup (dnode_end_t * zap_dnode, zap_phys_t * zap,
	     const char *name, grub_uint64_t * value,
	     struct grub_zfs_data *data, int case_insensitive)
{
  void *l;
  grub_uint64_t hash, idx, blkid;
  int blksft = zfs_log2 (grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
					    zap_dnode->endian) << DNODE_SHIFT);
  grub_err_t err;
  grub_zfs_endian_t leafendian;

  err = zap_verify (zap, zap_dnode->endian);
  if (err)
    return err;

  hash = zap_hash (zap->zap_salt, name, case_insensitive);

  /* get block id from index */
  if (zap->zap_ptrtbl.zt_numblks != 0)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
		       "external pointer tables not supported");
  idx = ZAP_HASH_IDX (hash, zap->zap_ptrtbl.zt_shift);
  blkid = grub_zfs_to_cpu64 (((grub_uint64_t *) zap)[idx + (1 << (blksft - 3 - 1))], zap_dnode->endian);

  /* Get the leaf block */
  if ((1U << blksft) < sizeof (zap_leaf_phys_t))
    return grub_error (GRUB_ERR_BAD_FS, "ZAP leaf is too small");
  err = dmu_read (zap_dnode, blkid, &l, &leafendian, data);
  if (err)
    return err;

  err = zap_leaf_lookup (l, leafendian, blksft, hash, name, value,
			 case_insensitive);
  grub_free (l);
  return err;
}

/* XXX */
static int
fzap_iterate (dnode_end_t * zap_dnode, zap_phys_t * zap,
	      grub_size_t name_elem_length,
	      int (*hook) (const void *name, grub_size_t name_length,
			    const void *val_in, grub_size_t nelem,
			    grub_size_t elemsize, void *data), 
	      void *hook_data, struct grub_zfs_data *data)
{
  zap_leaf_phys_t *l;
  void *l_in;
  grub_uint64_t idx, idx2, blkid;
  grub_uint16_t chunk;
  int blksft = zfs_log2 (grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
					    zap_dnode->endian) << DNODE_SHIFT);
  grub_err_t err;
  grub_zfs_endian_t endian;

  if (zap_verify (zap, zap_dnode->endian))
    return 0;

  /* get block id from index */
  if (zap->zap_ptrtbl.zt_numblks != 0)
    {
      grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, 
		  "external pointer tables not supported");
      return 0;
    }
  /* Get the leaf block */
  if ((1U << blksft) < sizeof (zap_leaf_phys_t))
    {
      grub_error (GRUB_ERR_BAD_FS, "ZAP leaf is too small");
      return 0;
    }
  for (idx = 0; idx < (1ULL << zap->zap_ptrtbl.zt_shift); idx++)
    {
      blkid = grub_zfs_to_cpu64 (((grub_uint64_t *) zap)[idx + (1 << (blksft - 3 - 1))],
					 zap_dnode->endian);

      for (idx2 = 0; idx2 < idx; idx2++)
	if (blkid == grub_zfs_to_cpu64 (((grub_uint64_t *) zap)[idx2 + (1 << (blksft - 3 - 1))],
					 zap_dnode->endian))
	  break;
      if (idx2 != idx)
	continue;

      err = dmu_read (zap_dnode, blkid, &l_in, &endian, data);
      l = l_in;
      if (err)
	{
	  grub_errno = GRUB_ERR_NONE;
	  continue;
	}

      /* Verify if this is a valid leaf block */
      if (grub_zfs_to_cpu64 (l->l_hdr.lh_block_type, endian) != ZBT_LEAF)
	{
	  grub_free (l);
	  continue;
	}
      if (grub_zfs_to_cpu32 (l->l_hdr.lh_magic, endian) != ZAP_LEAF_MAGIC)
	{
	  grub_free (l);
	  continue;
	}

      for (chunk = 0; chunk < ZAP_LEAF_NUMCHUNKS (blksft); chunk++)
	  {
	    char *buf;
	    struct zap_leaf_entry *le;
	    char *val;
	    grub_size_t val_length;
	    le = ZAP_LEAF_ENTRY (l, blksft, chunk);

	    /* Verify the chunk entry */
	    if (le->le_type != ZAP_CHUNK_ENTRY)
	      continue;

	    buf = grub_malloc (grub_zfs_to_cpu16 (le->le_name_length, endian)
			       * name_elem_length + 1);
	    if (zap_leaf_array_get (l, endian, blksft,
				    grub_zfs_to_cpu16 (le->le_name_chunk,
						       endian),
				    grub_zfs_to_cpu16 (le->le_name_length,
						       endian)
				    * name_elem_length, buf))
	      {
		grub_free (buf);
		continue;
	      }
	    buf[le->le_name_length * name_elem_length] = 0;

	    val_length = ((int) le->le_value_length
			  * (int) le->le_int_size);
	    val = grub_malloc (grub_zfs_to_cpu16 (val_length, endian));
	    if (zap_leaf_array_get (l, endian, blksft,
				    grub_zfs_to_cpu16 (le->le_value_chunk,
						       endian),
				    val_length, val))
	      {
		grub_free (buf);
		grub_free (val);
		continue;
	      }

	    if (hook (buf, le->le_name_length,
		      val, le->le_value_length, le->le_int_size, hook_data))
	      {
		grub_free (l);
		return 1;
	      }
	    grub_free (buf);
	    grub_free (val);
	  }
      grub_free (l);
    }
  return 0;
}

/*
 * Read in the data of a zap object and find the value for a matching
 * property name.
 *
 */
static grub_err_t
zap_lookup (dnode_end_t * zap_dnode, const char *name, grub_uint64_t *val,
	    struct grub_zfs_data *data, int case_insensitive)
{
  grub_uint64_t block_type;
  int size;
  void *zapbuf;
  grub_err_t err;
  grub_zfs_endian_t endian;

  grub_dprintf ("zfs", "looking for '%s'\n", name);

  /* Read in the first block of the zap object data. */
  size = grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
			    zap_dnode->endian) << SPA_MINBLOCKSHIFT;
  err = dmu_read (zap_dnode, 0, &zapbuf, &endian, data);
  if (err)
    return err;
  block_type = grub_zfs_to_cpu64 (*((grub_uint64_t *) zapbuf), endian);

  grub_dprintf ("zfs", "zap read\n");

  if (block_type == ZBT_MICRO)
    {
      grub_dprintf ("zfs", "micro zap\n");
      err = mzap_lookup (zapbuf, endian, size, name, val,
			 case_insensitive);
      grub_dprintf ("zfs", "returned %d\n", err);      
      grub_free (zapbuf);
      return err;
    }
  else if (block_type == ZBT_HEADER)
    {
      grub_dprintf ("zfs", "fat zap\n");
      /* this is a fat zap */
      err = fzap_lookup (zap_dnode, zapbuf, name, val, data,
			 case_insensitive);
      grub_dprintf ("zfs", "returned %d\n", err);      
      grub_free (zapbuf);
      return err;
    }

  return grub_error (GRUB_ERR_BAD_FS, "unknown ZAP type");
}

/*
 * Read in the data of a zap object and find the property name for a
 * matching value.
 *
 */
static grub_err_t
zap_value_search (dnode_end_t *zap_dnode, char *name, grub_uint64_t *val,
	    struct grub_zfs_data *data)
{
  grub_uint64_t block_type;
  int size;
  void *zapbuf;
  grub_err_t err;
  grub_zfs_endian_t endian;

  grub_dprintf ("zfs", "zap_value_search: looking for '%lld'\n", (unsigned long long)*val);

  /* Read in the first block of the zap object data. */
  size = grub_zfs_to_cpu16 (zap_dnode->dn.dn_datablkszsec, 
			    zap_dnode->endian) << SPA_MINBLOCKSHIFT;
  err = dmu_read (zap_dnode, 0, &zapbuf, &endian, data);
  if (err)
    return err;
  block_type = grub_zfs_to_cpu64 (*((grub_uint64_t *) zapbuf), endian);

  grub_dprintf ("zfs", "zap_value_search: zap read\n");

  if (block_type == ZBT_MICRO)
    {
      grub_dprintf ("zfs", "zap_value_search: micro zap value search\n");
      err = (mzap_value_search (zapbuf, endian, size, name, val));
      grub_dprintf ("zfs", "zap_value_search: returned %d\n", err);      
      grub_free (zapbuf);
      return err;
    }
  else if (block_type == ZBT_HEADER)
    {
      /* this is a fat zap */
      grub_dprintf ("zfs", "fat zap value search not supported\n");
      grub_free (zapbuf);
      return grub_error (GRUB_ERR_BAD_FS, "fat zap value search not supported");
    }

  return grub_error (GRUB_ERR_BAD_FS, "zap_value_search: unknown ZAP type");
}

/* Context for zap_iterate_u64.  */
struct zap_iterate_u64_ctx
{
	int (*hook) (const char *, grub_uint64_t, struct grub_zfs_dir_ctx *);
	struct grub_zfs_dir_ctx *dir_ctx;
};

/* Helper for zap_iterate_u64.  */
static int
zap_iterate_u64_transform (const void *name,
                           grub_size_t namelen __attribute__ ((unused)),
                           const void *val_in,
                           grub_size_t nelem,
                           grub_size_t elemsize,
                           void *data)
{
	struct zap_iterate_u64_ctx *ctx = data;

	if (elemsize != sizeof (grub_uint64_t) || nelem != 1)
		return 0;
	return ctx->hook(name,
	    grub_be_to_cpu64 (*(const grub_uint64_t *) val_in), ctx->dir_ctx);
}

static int
zap_iterate_u64 (dnode_end_t * zap_dnode, 
    int (*hook) (const char *name, grub_uint64_t val,
	struct grub_zfs_dir_ctx *ctx),
    struct grub_zfs_data *data, struct grub_zfs_dir_ctx *ctx)
{
	grub_uint64_t block_type;
	int size;
	void *zapbuf;
	grub_err_t err;
	int ret;
	grub_zfs_endian_t endian;

	/* Read in the first block of the zap object data. */
	size = grub_zfs_to_cpu16(zap_dnode->dn.dn_datablkszsec,
	    zap_dnode->endian) << SPA_MINBLOCKSHIFT;
	err = dmu_read (zap_dnode, 0, &zapbuf, &endian, data);
	if (err)
		return 0;
	block_type = grub_zfs_to_cpu64 (*((grub_uint64_t *) zapbuf), endian);

	grub_dprintf ("zfs", "zap iterate\n");

	if (block_type == ZBT_MICRO) {
		grub_dprintf ("zfs", "micro zap\n");
		ret = mzap_iterate (zapbuf, endian, size, hook, ctx);
		grub_free (zapbuf);
		return ret;
	} else if (block_type == ZBT_HEADER) {
		struct zap_iterate_u64_ctx transform_ctx = {
			.hook = hook,
			.dir_ctx = ctx
		};
		grub_dprintf ("zfs", "fat zap\n");
		/* this is a fat zap */
		ret = fzap_iterate (zap_dnode, zapbuf, 1,
		    zap_iterate_u64_transform, &transform_ctx, data);
		grub_free (zapbuf);
		return ret;
	}
	grub_error (GRUB_ERR_BAD_FS, "unknown ZAP type");
	return 0;
}

static int
zap_iterate (dnode_end_t * zap_dnode, grub_size_t nameelemlen,
    int (*hook) (const void *name, grub_size_t namelen, const void *val_in,
	grub_size_t nelem, grub_size_t elemsize, void *data),
    void *hook_data, struct grub_zfs_data *data)
{
	grub_uint64_t block_type;
	void *zapbuf;
	grub_err_t err;
	int ret;
	grub_zfs_endian_t endian;

	/* Read in the first block of the zap object data. */
	err = dmu_read(zap_dnode, 0, &zapbuf, &endian, data);
	if (err)
		return 0;
	block_type = grub_zfs_to_cpu64(*((grub_uint64_t *) zapbuf), endian);

	grub_dprintf("zfs", "zap iterate\n");

	if (block_type == ZBT_MICRO) {
		grub_error(GRUB_ERR_BAD_FS, "micro ZAP where FAT ZAP expected");
		return 0;
	}
	if (block_type == ZBT_HEADER) {
		grub_dprintf ("zfs", "fat zap\n");
		/* this is a fat zap */
		ret = fzap_iterate(zap_dnode, zapbuf, nameelemlen, hook,
		    hook_data, data);
		grub_free(zapbuf);
		return ret;
	}
	grub_error(GRUB_ERR_BAD_FS, "unknown ZAP type");
	return 0;
}


/*
 * Get the dnode of an object number from the metadnode of an object set.
 *
 * Input
 *	mdn - metadnode to get the object dnode
 *	objnum - object number for the object dnode
 *	buf - data buffer that holds the returning dnode
 */
static grub_err_t
dnode_get (dnode_end_t * mdn, grub_uint64_t objnum, grub_uint8_t type,
	   dnode_end_t * buf, struct grub_zfs_data *data)
{
  grub_uint64_t blkid, blksz;	/* the block id this object dnode is in */
  int epbs;			/* shift of number of dnodes in a block */
  int idx;			/* index within a block */
  void *dnbuf;
  grub_err_t err;
  grub_zfs_endian_t endian;

  blksz = grub_zfs_to_cpu16 (mdn->dn.dn_datablkszsec, 
			     mdn->endian) << SPA_MINBLOCKSHIFT;
  epbs = zfs_log2 (blksz) - DNODE_SHIFT;
  blkid = objnum >> epbs;
  idx = objnum & ((1 << epbs) - 1);

  if (data->dnode_buf != NULL && grub_memcmp (data->dnode_mdn, mdn, 
					      sizeof (*mdn)) == 0 
      && objnum >= data->dnode_start && objnum < data->dnode_end)
    {
      grub_memmove (&(buf->dn), &(data->dnode_buf)[idx], DNODE_SIZE);
      buf->endian = data->dnode_endian;
      if (type && buf->dn.dn_type != type) 
	return grub_error(GRUB_ERR_BAD_FS, "[1] incorrect dnode type: %d != %d\n", buf->dn.dn_type, type); 
      return GRUB_ERR_NONE;
    }

  grub_dprintf ("zfs", "endian = %d, blkid=%llx\n", mdn->endian, 
		(unsigned long long) blkid);
  err = dmu_read (mdn, blkid, &dnbuf, &endian, data);
  if (err)
    return err;
  grub_dprintf ("zfs", "alive\n");

  grub_free (data->dnode_buf);
  data->dnode_buf = NULL;
  grub_free (data->dnode_mdn);
  data->dnode_mdn = grub_malloc (sizeof (*mdn));
  if (! data->dnode_mdn)
    {
      grub_errno = GRUB_ERR_NONE;
      data->dnode_buf = 0;
    }
  else
    {
      grub_memcpy (data->dnode_mdn, mdn, sizeof (*mdn));
      data->dnode_buf = dnbuf;
      data->dnode_start = blkid << epbs;
      data->dnode_end = (blkid + 1) << epbs;
      data->dnode_endian = endian;
    }

  grub_memmove (&(buf->dn), (dnode_phys_t *) dnbuf + idx, DNODE_SIZE);
  buf->endian = endian;
  if (type && buf->dn.dn_type != type) 
    return grub_error(GRUB_ERR_BAD_FS, "[2] incorrect dnode type: %d != %d\n", buf->dn.dn_type, type); 

  return GRUB_ERR_NONE;
}

#pragma GCC diagnostic ignored "-Wstrict-aliasing"

/*
 * Get the file dnode for a given file name where mdn is the meta dnode
 * for this ZFS object set. When found, place the file dnode in dn.
 * The 'path' argument will be mangled.
 *
 */
static grub_err_t
dnode_get_path (struct subvolume *subvol, const char *path_in, dnode_end_t *dn,
		struct grub_zfs_data *data)
{
  grub_uint64_t objnum, version;
  char *cname, ch;
  grub_err_t err = GRUB_ERR_NONE;
  char *path, *path_buf;
  struct dnode_chain
  {
    struct dnode_chain *next;
    dnode_end_t dn; 
  };
  struct dnode_chain *dnode_path = 0, *dn_new, *root;

  dn_new = grub_malloc (sizeof (*dn_new));
  if (! dn_new)
    return grub_errno;
  dn_new->next = 0;
  dnode_path = root = dn_new;

  err = dnode_get (&subvol->mdn, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE, 
		   &(dnode_path->dn), data);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  err = zap_lookup (&(dnode_path->dn), ZPL_VERSION_STR, &version,
		    data, 0);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  if (version > ZPL_VERSION)
    {
      grub_free (dn_new);
      return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET, "too new ZPL version");
    }

  err = zap_lookup (&(dnode_path->dn), "casesensitivity",
		    &subvol->case_insensitive,
		    data, 0);
  if (err == GRUB_ERR_FILE_NOT_FOUND)
    {
      grub_errno = GRUB_ERR_NONE;
      subvol->case_insensitive = 0;
    }

  err = zap_lookup (&(dnode_path->dn), ZFS_ROOT_OBJ, &objnum, data, 0);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  err = dnode_get (&subvol->mdn, objnum, 0, &(dnode_path->dn), data);
  if (err)
    {
      grub_free (dn_new);
      return err;
    }

  path = path_buf = grub_strdup (path_in);
  if (!path_buf)
    {
      grub_free (dn_new);
      return grub_errno;
    }
  
  while (1)
    {
      /* skip leading slashes */
      while (*path == '/')
	path++;
      if (!*path)
	break;
      /* get the next component name */
      cname = path;
      while (*path && *path != '/')
	path++;
      /* Skip dot.  */
      if (cname + 1 == path && cname[0] == '.')
	continue;
      /* Handle double dot.  */
      if (cname + 2 == path && cname[0] == '.' && cname[1] == '.')
	{
	  if (dn_new->next)
	    {
	      dn_new = dnode_path;
	      dnode_path = dn_new->next;
	      grub_free (dn_new);
	    }
	  else
	    {
	      err = grub_error (GRUB_ERR_FILE_NOT_FOUND, 
				"can't resolve ..");
	      break;
	    }
	  continue;
	}

      ch = *path;
      *path = 0;		/* ensure null termination */

      if (dnode_path->dn.dn.dn_type != DMU_OT_DIRECTORY_CONTENTS)
	{
	  grub_free (path_buf);
	  return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("not a directory"));
	}
      err = zap_lookup (&(dnode_path->dn), cname, &objnum,
			data, subvol->case_insensitive);
      if (err)
	break;

      dn_new = grub_malloc (sizeof (*dn_new));
      if (! dn_new)
	{
	  err = grub_errno;
	  break;
	}
      dn_new->next = dnode_path;
      dnode_path = dn_new;

      objnum = ZFS_DIRENT_OBJ (objnum);
      err = dnode_get (&subvol->mdn, objnum, 0, &(dnode_path->dn), data);
      if (err)
	break;

      *path = ch;
      if (dnode_path->dn.dn.dn_bonustype == DMU_OT_ZNODE
	  && ((grub_zfs_to_cpu64(((znode_phys_t *) DN_BONUS (&dnode_path->dn.dn))->zp_mode, dnode_path->dn.endian) >> 12) & 0xf) == 0xa)
	{
	  char *sym_value;
	  grub_size_t sym_sz;
	  int free_symval = 0;
	  char *oldpath = path, *oldpathbuf = path_buf;
	  sym_value = ((char *) DN_BONUS (&dnode_path->dn.dn) + sizeof (struct znode_phys));

	  sym_sz = grub_zfs_to_cpu64 (((znode_phys_t *) DN_BONUS (&dnode_path->dn.dn))->zp_size, dnode_path->dn.endian);

	  if (dnode_path->dn.dn.dn_flags & 1)
	    {
	      grub_size_t block;
	      grub_size_t blksz;
	      blksz = (grub_zfs_to_cpu16 (dnode_path->dn.dn.dn_datablkszsec, 
					 dnode_path->dn.endian)
		       << SPA_MINBLOCKSHIFT);

	      if (blksz == 0)
		return grub_error(GRUB_ERR_BAD_FS, "0-sized block");

	      sym_value = grub_malloc (sym_sz);
	      if (!sym_value)
		return grub_errno;
	      for (block = 0; block < (sym_sz + blksz - 1) / blksz; block++)
		{
		  void *t;
		  grub_size_t movesize;

		  err = dmu_read (&(dnode_path->dn), block, &t, 0, data);
		  if (err)
		    return err;

		  movesize = sym_sz - block * blksz;
		  if (movesize > blksz)
		    movesize = blksz;

		  grub_memcpy (sym_value + block * blksz, t, movesize);
		  grub_free (t);
		}
	      free_symval = 1;
	    }	    
	  path = path_buf = grub_malloc (sym_sz + grub_strlen (oldpath) + 1);
	  if (!path_buf)
	    {
	      grub_free (oldpathbuf);
	      if (free_symval)
		grub_free (sym_value);
	      return grub_errno;
	    }
	  grub_memcpy (path, sym_value, sym_sz);
	  if (free_symval)
	    grub_free (sym_value);
	  path [sym_sz] = 0;
	  grub_memcpy (path + grub_strlen (path), oldpath, 
		       grub_strlen (oldpath) + 1);
	  
	  grub_free (oldpathbuf);
	  if (path[0] != '/')
	    {
	      dn_new = dnode_path;
	      dnode_path = dn_new->next;
	      grub_free (dn_new);
	    }
	  else while (dnode_path != root)
	    {
	      dn_new = dnode_path;
	      dnode_path = dn_new->next;
	      grub_free (dn_new);
	    }
	}
      if (dnode_path->dn.dn.dn_bonustype == DMU_OT_SA)
	{
	  void *sahdrp;
	  int hdrsize;
	  
	  if (dnode_path->dn.dn.dn_bonuslen != 0)
	    {
	      sahdrp = DN_BONUS (&dnode_path->dn.dn);
	    }
	  else if (dnode_path->dn.dn.dn_flags & DNODE_FLAG_SPILL_BLKPTR)
	    {
	      blkptr_t *bp = &dnode_path->dn.dn.dn_spill;
	      
	      err = zio_read (bp, dnode_path->dn.endian, &sahdrp, NULL, data);
	      if (err)
		return err;
	    }
	  else
	    {
	      return grub_error (GRUB_ERR_BAD_FS, "filesystem is corrupt");
	    }

	  hdrsize = SA_HDR_SIZE (((sa_hdr_phys_t *) sahdrp));

	  if (((grub_zfs_to_cpu64 (grub_get_unaligned64 ((char *) sahdrp
							 + hdrsize
							 + SA_TYPE_OFFSET),
				   dnode_path->dn.endian) >> 12) & 0xf) == 0xa)
	    {
	      char *sym_value = (char *) sahdrp + hdrsize + SA_SYMLINK_OFFSET;
	      grub_size_t sym_sz = 
		grub_zfs_to_cpu64 (grub_get_unaligned64 ((char *) sahdrp
							 + hdrsize
							 + SA_SIZE_OFFSET),
				   dnode_path->dn.endian);
	      char *oldpath = path, *oldpathbuf = path_buf;
	      path = path_buf = grub_malloc (sym_sz + grub_strlen (oldpath) + 1);
	      if (!path_buf)
		{
		  grub_free (oldpathbuf);
		  return grub_errno;
		}
	      grub_memcpy (path, sym_value, sym_sz);
	      path [sym_sz] = 0;
	      grub_memcpy (path + grub_strlen (path), oldpath, 
			   grub_strlen (oldpath) + 1);
	      
	      grub_free (oldpathbuf);
	      if (path[0] != '/')
		{
		  dn_new = dnode_path;
		  dnode_path = dn_new->next;
		  grub_free (dn_new);
		}
	      else while (dnode_path != root)
		{
		  dn_new = dnode_path;
		  dnode_path = dn_new->next;
		  grub_free (dn_new);
		}
	    }
	}
    }

  if (!err)
    grub_memcpy (dn, &(dnode_path->dn), sizeof (*dn));

  while (dnode_path)
    {
      dn_new = dnode_path->next;
      grub_free (dnode_path);
      dnode_path = dn_new;
    }
  grub_free (path_buf);
  return err;
}

/*
 * Get the default 'bootfs' dataset name using rootfs object number
 *
 */
static grub_err_t
get_default_bootfsname (dnode_end_t * mosmdn, grub_uint64_t bootfsobj,
		       struct grub_zfs_data *data, char **bootfsname)
{
  dnode_end_t dn;
  dnode_end_t mdn;
  grub_uint64_t dirobj;
  grub_uint64_t parentobj;
  grub_uint64_t childobj;
  grub_uint64_t rootobj;
  grub_size_t	buf_size;
  grub_err_t err = GRUB_ERR_NONE;
  char *bootfs;

  *bootfsname = 0;
  if ((grub_errno = dnode_get (mosmdn, DMU_POOL_DIRECTORY_OBJECT,
			       DMU_OT_OBJECT_DIRECTORY, &mdn, data)))
      return (grub_errno);

  err = zap_lookup (&mdn, DMU_POOL_ROOT_DATASET, &rootobj, data, 0);
  if (err)
       return err;

  if ((grub_errno = dnode_get (mosmdn, bootfsobj, DMU_OT_DSL_DATASET, &dn, data)))
       return (grub_errno);

  dirobj = grub_zfs_to_cpu64 (((dsl_dataset_phys_t *)
			DN_BONUS (&dn.dn))->ds_dir_obj, dn.endian);

  buf_size = BOOTFSNAME_SIZE;
  bootfs = grub_zalloc(buf_size);
  do
    {
      if ((grub_errno = dnode_get (mosmdn, dirobj, DMU_OT_DSL_DIR, &dn, data))) 
	{
	  grub_free (bootfs);
          return (grub_errno);
	}

      parentobj = grub_zfs_to_cpu64 ((((dsl_dir_phys_t *)
			    DN_BONUS (&dn.dn)))->dd_parent_obj, dn.endian);

      if ((grub_errno = dnode_get (mosmdn, parentobj, DMU_OT_DSL_DIR, &dn, data)))
	{
	  grub_free (bootfs);
          return (grub_errno);
	}

      childobj = grub_zfs_to_cpu64 ((((dsl_dir_phys_t *)
			    DN_BONUS (&dn.dn)))->dd_child_dir_zapobj, dn.endian);
  
      if ((grub_errno = dnode_get (mosmdn, childobj,
				   DMU_OT_DSL_DIR_CHILD_MAP, &dn, data)))
	{
	  grub_free (bootfs);
          return (grub_errno);
	}

      char cname[64]; 
      grub_memset (cname, 0, sizeof(cname));

      if (zap_value_search (&dn, cname, &dirobj, data))
	{
	  grub_free (bootfs);
          return (GRUB_ERR_BAD_FS);
	}

      grub_size_t cname_len = grub_strlen(cname);
      cname[cname_len++] = '/';

      grub_size_t bootfs_len= grub_strlen(bootfs);
      grub_size_t expected_len = bootfs_len + cname_len;
      if (expected_len >= buf_size)
	{
	    while((buf_size = buf_size * 2) < expected_len);
	    char *tmp = grub_realloc (bootfs, buf_size);
	    if (! tmp)
	      {
		grub_free (bootfs);
		return (grub_errno);
	      }
	    bootfs = tmp;
	    grub_memset((bootfs + bootfs_len), 0, (buf_size - bootfs_len));
	}

      /* create space for parent dataset name */
      grub_memmove((bootfs + cname_len), bootfs, bootfs_len); 
      grub_memmove(bootfs, cname, cname_len);

    } while ((dirobj = parentobj) != rootobj);

  /* remove trailing slash */
  *(bootfs + grub_strlen(bootfs) - 1) = '\0';
  *bootfsname = bootfs;

  grub_dprintf ("zfs", "get_default_bootfsname: %s\n", *bootfsname);
  return (0);
}

/*
 * Get the default 'bootfs' property value from the rootpool.
 *
 */
static grub_err_t
get_default_bootfsobj (dnode_end_t * mosmdn, grub_uint64_t * obj,
		       struct grub_zfs_data *data)
{
  grub_uint64_t objnum = 0;
  dnode_end_t dn;

  grub_dprintf ("zfs", "get_default_bootfsobj called\n");
  if ((grub_errno = dnode_get (mosmdn, DMU_POOL_DIRECTORY_OBJECT,
			       DMU_OT_OBJECT_DIRECTORY, &dn, data)))
      return (grub_errno);

  /*
   * find the object number for 'pool_props', and get the dnode
   * of the 'pool_props'.
   */
  if (zap_lookup (&dn, DMU_POOL_PROPS, &objnum, data, 0))
      return (GRUB_ERR_BAD_FS);

  if ((grub_errno = dnode_get (mosmdn, objnum, DMU_OT_POOL_PROPS, &dn, data)))
      return (grub_errno);

  if (zap_lookup (&dn, ZPOOL_PROP_BOOTFS, &objnum, data, 0))
      return (GRUB_ERR_BAD_FS);

  if (!objnum)
      return (GRUB_ERR_BAD_FS);
  
  *obj = objnum;

  return (0);
}

/*
 * Given a MOS metadnode, get the metadnode of a given filesystem name (fsname),
 * e.g. pool/rootfs, or a given object number (obj), e.g. the object number
 * of pool/rootfs.
 *
 * If no fsname and no obj are given, return the DSL_DIR metadnode.
 * If fsname is given, return its metadnode and its matching object number.
 * If only obj is given, return the metadnode for this object number.
 *
 */
static grub_err_t
get_filesystem_dnode (dnode_end_t * mosmdn, char *fsname,
		      dnode_end_t * mdn, struct grub_zfs_data *data)
{
  grub_uint64_t objnum;
  grub_err_t err;

  grub_dprintf ("zfs", "endian = %d\n", mosmdn->endian);

  err = dnode_get (mosmdn, DMU_POOL_DIRECTORY_OBJECT, 
		   DMU_OT_OBJECT_DIRECTORY, mdn, data);
  if (err)
    return err;

  grub_dprintf ("zfs", "alive\n");

  err = zap_lookup (mdn, DMU_POOL_ROOT_DATASET, &objnum, data, 0);
  if (err)
    return err;

  grub_dprintf ("zfs", "alive\n");

  err = dnode_get (mosmdn, objnum, DMU_OT_DSL_DIR, mdn, data);
  if (err)
    return err;

  grub_dprintf ("zfs", "alive\n");

  while (*fsname)
    {
      grub_uint64_t childobj;
      char *cname, ch;
 
      while (*fsname == '/')
	fsname++;

      if (! *fsname || *fsname == '@')
	break;

      cname = fsname;
      while (*fsname && !grub_isspace (*fsname) && *fsname != '/')
	fsname++;
      ch = *fsname;
      *fsname = 0;

      childobj = grub_zfs_to_cpu64 ((((dsl_dir_phys_t *) DN_BONUS (&mdn->dn)))->dd_child_dir_zapobj, mdn->endian);
      if (childobj == 0)
	return grub_error(GRUB_ERR_BAD_FS, "file system not found");

      err = dnode_get (mosmdn, childobj,
		       DMU_OT_DSL_DIR_CHILD_MAP, mdn, data);
      if (err)
	return err;

      err = zap_lookup (mdn, cname, &objnum, data, 0);
      if (err)
	return err;

      err = dnode_get (mosmdn, objnum, DMU_OT_DSL_DIR, mdn, data);
      if (err)
	return err;

      *fsname = ch;
    }
  return GRUB_ERR_NONE;
}

static grub_err_t
make_mdn (dnode_end_t * mdn, struct grub_zfs_data *data)
{
  void *osp;
  blkptr_t *bp;
  grub_size_t ospsize;
  grub_err_t err;

  grub_dprintf ("zfs", "endian = %d\n", mdn->endian);

  bp = &(((dsl_dataset_phys_t *) DN_BONUS (&mdn->dn))->ds_bp);
  err = zio_read (bp, mdn->endian, &osp, &ospsize, data);
  if (err)
    return err;
  if (ospsize < OBJSET_PHYS_SIZE_V14)
    {
      grub_free (osp);
      return grub_error (GRUB_ERR_BAD_FS, "too small osp");
    }

  mdn->endian = (grub_zfs_to_cpu64 (bp->blk_prop, mdn->endian)>>63) & 1;
  grub_memmove ((char *) &(mdn->dn),
		(char *) &((objset_phys_t *) osp)->os_meta_dnode, DNODE_SIZE);
  grub_free (osp);
  return GRUB_ERR_NONE;
}

/* Context for dnode_get_fullpath.  */
struct dnode_get_fullpath_ctx
{
	struct subvolume *subvol;
	grub_uint64_t salt;
	int keyn;
};

/* Helper for dnode_get_fullpath.  */
static int
count_zap_keys (const void *name __attribute__ ((unused)),
    grub_size_t namelen __attribute__ ((unused)),
    const void *val_in __attribute__ ((unused)),
    grub_size_t nelem __attribute__ ((unused)),
    grub_size_t elemsize __attribute__ ((unused)),
    void *data)
{
	struct dnode_get_fullpath_ctx *ctx = data;

	ctx->subvol->nkeys++;
	return 0;
}

/* Helper for dnode_get_fullpath. */
static int
load_zap_key (const void *name, grub_size_t namelen, const void *val_in,
    grub_size_t nelem, grub_size_t elemsize, void *data)
{
	struct dnode_get_fullpath_ctx *ctx = data;

	if (namelen != 1) {
		grub_dprintf("zfs",
		    "Unexpected key index size %" PRIuGRUB_SIZE "\n", namelen);
		return 0;
	}

	if (elemsize != 1) {
		grub_dprintf("zfs",
		    "Unexpected key element size %" PRIuGRUB_SIZE "\n",
		    elemsize);
		return 0;
	}

	ctx->subvol->keyring[ctx->keyn].txg =
	    grub_be_to_cpu64(*(grub_uint64_t *) name);
	ctx->subvol->keyring[ctx->keyn].algo =
	    grub_le_to_cpu64(*(grub_uint64_t *) val_in);
	ctx->subvol->keyring[ctx->keyn].cipher =
	    grub_zfs_load_key(val_in, nelem, ctx->salt,
	    ctx->subvol->keyring[ctx->keyn].algo);
	ctx->keyn++;
	return 0;
}

static grub_err_t
dnode_get_fullpath (const char *fullpath, struct subvolume *subvol,
    dnode_end_t *dn, int *isfs, struct grub_zfs_data *data)
{
	char *fsname, *snapname;
	const char *ptr_at, *filename;
	grub_uint64_t headobj;
	grub_uint64_t keychainobj;
	grub_err_t err;

	ptr_at = grub_strchr(fullpath, '@');
	if (!ptr_at) {
		*isfs = 1;
		filename = 0;
		snapname = 0;
		fsname = grub_strdup(fullpath);
	} else {
		const char *ptr_slash = grub_strchr(ptr_at, '/');

		*isfs = 0;
		fsname = grub_malloc(ptr_at - fullpath + 1);
		if (!fsname)
			return grub_errno;
		grub_memcpy(fsname, fullpath, ptr_at - fullpath);
		fsname[ptr_at - fullpath] = 0;
		if (ptr_at[1] && ptr_at[1] != '/') {
			snapname = grub_malloc(ptr_slash - ptr_at);
			if (!snapname) {
				grub_free(fsname);
				return grub_errno;
			}
			grub_memcpy(snapname, ptr_at + 1,
			    ptr_slash - ptr_at - 1);
			snapname[ptr_slash - ptr_at - 1] = 0;
		} else
			snapname = 0;
		if (ptr_slash)
			filename = ptr_slash;
		else
			filename = "/";
		grub_dprintf("zfs",
		    "fsname = '%s' snapname='%s' filename = '%s'\n", 
		    fsname, snapname, filename);
	}
	grub_dprintf ("zfs", "alive\n");
	err = get_filesystem_dnode(&(data->mos), fsname, dn, data);
	if (err) {
		grub_free(fsname);
		grub_free(snapname);
		return err;
	}

	grub_dprintf("zfs", "alive\n");

	headobj = grub_zfs_to_cpu64(
	    ((dsl_dir_phys_t *) DN_BONUS(&dn->dn))->dd_head_dataset_obj,
	    dn->endian);

	grub_dprintf("zfs", "endian = %d\n", subvol->mdn.endian);

	err = dnode_get(&(data->mos), headobj, DMU_OT_DSL_DATASET,
	    &subvol->mdn, data);
	if (err) {
		grub_free(fsname);
		grub_free(snapname);
		return err;
	}
	grub_dprintf ("zfs", "endian = %d\n", subvol->mdn.endian);

	keychainobj = grub_zfs_to_cpu64 (
	    ((dsl_dir_phys_t *) DN_BONUS(&dn->dn))->keychain, dn->endian);
	if (grub_zfs_load_key && keychainobj) {
		struct dnode_get_fullpath_ctx ctx = {
			.subvol = subvol,
			.keyn = 0
		};
		dnode_end_t keychain_dn, props_dn;
		grub_uint64_t propsobj;
		propsobj = grub_zfs_to_cpu64(
		    ((dsl_dir_phys_t *) DN_BONUS(&dn->dn))->dd_props_zapobj,
		    dn->endian);

		err = dnode_get(&(data->mos), propsobj, DMU_OT_DSL_PROPS,
		    &props_dn, data);
		if (err) {
			grub_free(fsname);
			grub_free(snapname);
			return err;
		}

		err = zap_lookup (&props_dn, "salt", &ctx.salt, data, 0);
		if (err == GRUB_ERR_FILE_NOT_FOUND) {
			err = 0;
			grub_errno = 0;
			ctx.salt = 0;
		}
		if (err) {
			grub_dprintf("zfs", "failed here\n");
			return err;
		}

		err = dnode_get(&(data->mos), keychainobj, DMU_OT_DSL_KEYCHAIN,
		    &keychain_dn, data);
		if (err) {
			grub_free(fsname);
			grub_free(snapname);
			return err;
		}
		subvol->nkeys = 0;
		zap_iterate(&keychain_dn, 8, count_zap_keys, &ctx, data);
		subvol->keyring = grub_zalloc(subvol->nkeys *
		    sizeof (subvol->keyring[0]));
		if (!subvol->keyring) {
			grub_free(fsname);
			grub_free(snapname);
			return err;
		}
		zap_iterate(&keychain_dn, 8, load_zap_key, &ctx, data);
	}

	if (snapname) {
		grub_uint64_t snapobj;

		snapobj = grub_zfs_to_cpu64(
		    ((dsl_dataset_phys_t *)
		    DN_BONUS(&subvol->mdn.dn))->ds_snapnames_zapobj,
		    subvol->mdn.endian);

		err = dnode_get(&(data->mos), snapobj, 
		    DMU_OT_DSL_DS_SNAP_MAP, &subvol->mdn, data);
		if (!err)
			err = zap_lookup(&subvol->mdn, snapname,
			    &headobj, data, 0);
		if (!err)
			err = dnode_get(&(data->mos), headobj,
			    DMU_OT_DSL_DATASET, &subvol->mdn, data);
		if (err) {
			grub_free(fsname);
			grub_free(snapname);
			return err;
		}
	}

	subvol->obj = headobj;

	make_mdn(&subvol->mdn, data);
  
	grub_dprintf("zfs", "endian = %d\n", subvol->mdn.endian);

	if (*isfs) {
		grub_free(fsname);
		grub_free(snapname);      
		return GRUB_ERR_NONE;
	}
	err = dnode_get_path(subvol, filename, dn, data);
	grub_free(fsname);
	grub_free(snapname);
	return err;
}

/*
 * Checks whether the MOS features that are active are supported by this
 * (GRUB's) implementation of ZFS.
 *
 * Return:
 *      0: Success.
 *      errnum: Failure.
 */
static grub_err_t
check_mos_features(dnode_end_t *mosmdn, struct grub_zfs_data *data)
{
        dnode_end_t dn;
        grub_uint64_t objnum;
        grub_err_t errnum = GRUB_ERR_NONE;

        if ((errnum = dnode_get(mosmdn, DMU_POOL_DIRECTORY_OBJECT,
            DMU_OT_OBJECT_DIRECTORY, &dn, data)) != 0)
                return (errnum);

        /*
         * Find the object number for 'features_for_read' and retrieve its
         * corresponding dnode. Note that we don't check features_for_write
         * because GRUB is not opening the pool for write.
         */
        errnum = zap_lookup(&dn, DMU_POOL_FEATURES_FOR_READ, &objnum, data, 0);
	if(errnum != 0) {
	  /* this pool does not support features */
	  if(errnum == GRUB_ERR_FILE_NOT_FOUND)
		errnum = GRUB_ERR_NONE;

          return (errnum);
	}

        if ((errnum = dnode_get(mosmdn, objnum, DMU_OTN_ZAP_METADATA,
            &dn, data)) != 0)
                return (errnum);

        return (zap_iterate_u64(&dn, check_feature, data, NULL));
}

/*
 * For a given XDR packed nvlist, verify the first 4 bytes and move on.
 *
 * An XDR packed nvlist is encoded as (comments from nvs_xdr_create) :
 *
 *      encoding method/host endian     (4 bytes)
 *      nvl_version                     (4 bytes)
 *      nvl_nvflag                      (4 bytes)
 *	encoded nvpairs:
 *		encoded size of the nvpair      (4 bytes)
 *		decoded size of the nvpair      (4 bytes)
 *		name string size                (4 bytes)
 *		name string data                (sizeof(NV_ALIGN4(string))
 *		data type                       (4 bytes)
 *		# of elements in the nvpair     (4 bytes)
 *		data
 *      2 zero's for the last nvpair
 *		(end of the entire list)	(8 bytes)
 *
 */

/*
 * The nvlist_next_nvpair() function returns a handle to the next nvpair in the
 * list following nvpair. If nvpair is NULL, the first pair is returned. If
 * nvpair is the last pair in the nvlist, NULL is returned.
 */
static const char *
nvlist_next_nvpair (const char *nvl, const char *nvpair)
{
  const char *nvp;
  int encode_size;
  int name_len;
  if (nvl == NULL)
    return NULL;

  if (nvpair == NULL)
    {
      /* skip over header, nvl_version and nvl_nvflag */
      nvpair = nvl + 4 * 3;
    } 
  else
    {
      /* skip to the next nvpair */
      encode_size = grub_be_to_cpu32 (grub_get_unaligned32(nvpair));
      nvpair += encode_size;
      /*If encode_size equals 0 nvlist_next_nvpair would return
       * the same pair received in input, leading to an infinite loop.
       * If encode_size is less than 0, this will move the pointer
       * backwards, *possibly* examinining two times the same nvpair
       * and potentially getting into an infinite loop. */
      if(encode_size <= 0)
	{
	  grub_dprintf ("zfs", "nvpair with size <= 0\n");
	  grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist");
	  return NULL;
	}
    }
  /* 8 bytes of 0 marks the end of the list */
  if (grub_get_unaligned64 (nvpair) == 0)
    return NULL;
  /*consistency checks*/
  if (nvpair + 4 * 3 >= nvl + VDEV_PHYS_SIZE)
    {
      grub_dprintf ("zfs", "nvlist overflow\n");
      grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist");
      return NULL;
    }
  encode_size = grub_be_to_cpu32 (grub_get_unaligned32(nvpair));

  nvp = nvpair + 4*2;
  name_len = grub_be_to_cpu32 (grub_get_unaligned32 (nvp));
  nvp += 4;

  nvp = nvp + ((name_len + 3) & ~3); // align 
  if (nvp + 4 >= nvl + VDEV_PHYS_SIZE                        
      || encode_size < 0
      || nvp + 4 + encode_size > nvl + VDEV_PHYS_SIZE)       
    {
      grub_dprintf ("zfs", "nvlist overflow\n");
      grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist");
      return NULL;
    }
  /* end consistency checks */

  return nvpair;
}

/*
 * This function returns 0 on success and 1 on failure. On success, a string
 * containing the name of nvpair is saved in buf.
 */
static char *
nvpair_name(const char *nvp)
{
	int len;
	char *buf = NULL;
 
	/* skip over encode/decode size */
	nvp += 4 * 2;
	len = grub_be_to_cpu32 (grub_get_unaligned32 (nvp));
	buf = grub_malloc(len + 1);
	if (buf ) {
		grub_memmove(buf, nvp + 4, len);
		buf[len] = '\0';
	}
	return buf;
}

#if 0
/*
 * This function retrieves the value of the nvpair in the form of enumerated
 * type data_type_t.
 */
static int
nvpair_type (const char *nvp)
{
  int name_len, type;

  /* skip over encode/decode size */
  nvp += 4 * 2;

  /* skip over name_len */
  name_len = grub_be_to_cpu32 (grub_get_unaligned32 (nvp));
  nvp += 4;

  /* skip over name */
  nvp = nvp + ((name_len + 3) & ~3); /* align */

  type = grub_be_to_cpu32 (grub_get_unaligned32 (nvp));

  return type;
}

static int
nvpair_value (const char *nvp,char **val,
	      grub_size_t *size_out, grub_size_t *nelm_out)
{
  int name_len,nelm,encode_size;

  /* skip over encode/decode size */
  encode_size = grub_be_to_cpu32 (grub_get_unaligned32(nvp));
  nvp += 8;

  /* skip over name_len */
  name_len = grub_be_to_cpu32 (grub_get_unaligned32 (nvp));
  nvp += 4;

  /* skip over name */
  nvp = nvp + ((name_len + 3) & ~3); /* align */
	
  /* skip over type */
  nvp += 4;
  nelm = grub_be_to_cpu32 (grub_get_unaligned32 (nvp));
  nvp +=4;
  if (nelm < 1)
    {
      grub_error (GRUB_ERR_BAD_FS, "empty nvpair");
      return 0;
    }
  *val = (char *) nvp;
  *size_out = encode_size;
  if (nelm_out)
    *nelm_out = nelm;
	    
  return 1;
}
#endif

static int
nvlist_find_value (const char *nvlist_in, const char *name,
		   int valtype, char **val,
		   grub_size_t *size_out, grub_size_t *nelm_out)
{
  int name_len, type, encode_size;
  const char *nvpair, *nvp_name, *nvlist = nvlist_in;

  /* Verify if the 1st and 2nd byte in the nvlist are valid. */
  /* NOTE: independently of what endianness header announces all 
     subsequent values are big-endian.  */
  if (nvlist[0] != NV_ENCODE_XDR || (nvlist[1] != NV_LITTLE_ENDIAN 
				     && nvlist[1] != NV_BIG_ENDIAN))
    {
      grub_dprintf ("zfs", "incorrect nvlist header\n");
      grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist");
      return 0;
    }

  /* skip the header, nvl_version, and nvl_nvflag */
  nvlist = nvlist + 4 * 3;
  /*
   * Loop thru the nvpair list
   * The XDR representation of an integer is in big-endian byte order.
   */
  while ((encode_size = grub_be_to_cpu32 (grub_get_unaligned32 (nvlist))))
    {
      int nelm;

      if (nvlist + 4 * 4 >= nvlist_in + VDEV_PHYS_SIZE)
	{
	  grub_dprintf("zfs", "nvlist overflow\n");
	  grub_error(GRUB_ERR_BAD_FS, "incorrect nvlist");
	  return 0;
	}

      nvpair = nvlist + 4 * 2;	/* skip the encode/decode size */

      name_len = grub_be_to_cpu32 (grub_get_unaligned32 (nvpair));
      nvpair += 4;

      nvp_name = nvpair;
      nvpair = nvpair + ((name_len + 3) & ~3);	/* align */

      if (nvpair + 8 >= nvlist_in + VDEV_PHYS_SIZE
	  || encode_size < 0
	  || nvpair + 8 + encode_size > nvlist_in + VDEV_PHYS_SIZE)
	{
	  grub_dprintf("zfs", "nvlist overflow\n");
	  grub_error(GRUB_ERR_BAD_FS, "incorrect nvlist");
	  return 0;
	}

      type = grub_be_to_cpu32 (grub_get_unaligned32 (nvpair));
      nvpair += 4;

      nelm = grub_be_to_cpu32 (grub_get_unaligned32 (nvpair));
      if (nelm < 1)
	return grub_error (GRUB_ERR_BAD_FS, "empty nvpair");

      nvpair += 4;

      if ((grub_strncmp (nvp_name, name, name_len) == 0) && type == valtype)
	{
	  *val = (char *) nvpair;
	  *size_out = encode_size;
	  if (nelm_out)
	    *nelm_out = nelm;
	  return 1;
	}

      nvlist += encode_size;	/* goto the next nvpair */
    }
  return 0;
}

int
grub_zfs_nvlist_lookup_uint64 (const char *nvlist, const char *name,
			       grub_uint64_t * out)
{
  char *nvpair;
  grub_size_t size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_UINT64, &nvpair, &size, 0);
  if (!found)
    return 0;
  if (size < sizeof (grub_uint64_t))
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid uint64");
      return 0;
    }

  *out = grub_be_to_cpu64 (grub_get_unaligned64 (nvpair));
  return 1;
}

char *
grub_zfs_nvlist_lookup_string (const char *nvlist, const char *name)
{
  char *nvpair;
  char *ret;
  grub_size_t slen;
  grub_size_t size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_STRING, &nvpair, &size, 0);
  if (!found)
    return 0;
  if (size < 4)
    {
      grub_error (GRUB_ERR_BAD_FS, "invalid string");
      return 0;
    }
  slen = grub_be_to_cpu32 (grub_get_unaligned32 (nvpair));
  if (slen > size - 4)
    slen = size - 4;
  ret = grub_malloc (slen + 1);
  if (!ret)
    return 0;
  grub_memcpy (ret, nvpair + 4, slen);
  ret[slen] = 0;
  return ret;
}

char *
grub_zfs_nvlist_lookup_nvlist (const char *nvlist, const char *name)
{
  char *nvpair;
  char *ret;
  grub_size_t size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_NVLIST, &nvpair,
			     &size, 0);
  if (!found)
    return 0;
  ret = grub_zalloc (size + 3 * sizeof (grub_uint32_t));
  if (!ret)
    return 0;
  grub_memcpy (ret, nvlist, sizeof (grub_uint32_t));

  grub_memcpy (ret + sizeof (grub_uint32_t), nvpair, size);
  return ret;
}

int
grub_zfs_nvlist_lookup_nvlist_array_get_nelm (const char *nvlist,
					      const char *name)
{
  char *nvpair;
  grub_size_t nelm, size;
  int found;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_NVLIST_ARRAY, &nvpair,
			     &size, &nelm);
  if (! found)
    return -1;
  return nelm;
}

static int
get_nvlist_size (const char *beg, const char *limit)
{
  const char *ptr;
  grub_uint32_t encode_size;
  
  ptr = beg + 8;

  while (ptr < limit
	 && (encode_size = grub_be_to_cpu32 (grub_get_unaligned32 (ptr))))
    ptr += encode_size;	/* goto the next nvpair */
  ptr += 8;      
  return (ptr > limit) ? -1 : (ptr - beg);
}

char *
grub_zfs_nvlist_lookup_nvlist_array (const char *nvlist, const char *name,
				     grub_size_t index)
{
  char *nvpair, *nvpairptr;
  int found;
  char *ret;
  grub_size_t size;
  unsigned i;
  grub_size_t nelm;
  int elemsize = 0;

  found = nvlist_find_value (nvlist, name, DATA_TYPE_NVLIST_ARRAY, &nvpair,
			     &size, &nelm);
  if (!found)
    return 0;
  if (index >= nelm)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, "trying to lookup past nvlist array");
      return 0;
    }

  nvpairptr = nvpair;

  for (i = 0; i < index; i++)
    {
      int r;
      r = get_nvlist_size (nvpairptr, nvpair + size);

      if (r < 0)
	{
	  grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist array");
	  return NULL;
	}
      nvpairptr += r;
    }

  elemsize = get_nvlist_size (nvpairptr, nvpair + size);

  if (elemsize < 0)
    {
      grub_error (GRUB_ERR_BAD_FS, "incorrect nvlist array");
      return 0;
    }

  ret = grub_zalloc (elemsize + sizeof (grub_uint32_t));
  if (!ret)
    return 0;
  grub_memcpy (ret, nvlist, sizeof (grub_uint32_t));

  grub_memcpy (ret + sizeof (grub_uint32_t), nvpairptr, elemsize);
  return ret;
}

static void
unmount_device (struct grub_zfs_device_desc *desc)
{
  unsigned i;
  switch (desc->type)
    {
    case DEVICE_LEAF:
      if (!desc->original && desc->dev)
	grub_device_close (desc->dev);
      return;
    case DEVICE_RAIDZ:
    case DEVICE_MIRROR:
      for (i = 0; i < desc->n_children; i++)
	unmount_device (&desc->children[i]);
      return;
    }
}

static void
zfs_unmount (struct grub_zfs_data *data)
{
  unsigned i;

  grub_free (data->dnode_buf);
  data->dnode_buf = NULL;
  grub_free (data->dnode_mdn);
  data->dnode_mdn = NULL;
  grub_free (data->file_buf);
  data->file_buf = NULL;
  for (i = 0; i < data->subvol.nkeys; i++)
    grub_crypto_cipher_close (data->subvol.keyring[i].cipher);
  grub_free (data->subvol.keyring);
  data->subvol.nkeys = 0;
  data->subvol.keyring = NULL;

  data->mount_count--;
  if (! data->zcached)
    {
      for (i = 0; i < data->n_devices_attached; i++)
        {
          unmount_device (&data->devices_attached[i]);
          grub_free (data->devices_attached[i].children);
        }
      grub_free (data->devices_attached);
      grub_free (data);
    }
}

/*
 * Free all the caches
 */
static void
zfs_free_caches (void)
{
  unsigned int i;
  struct grub_zfs_data *data;
  struct zfs_mount_cache *zcache, *zcache_next;
  struct zfs_dev_notzfs *dev_notzfs, *dev_notzfs_next;
  struct zfs_dev_ublock *dev_ub, *dev_ub_next;

  /* free the zfs mount cache list */
  zcache = zfs_mount_cache_list;
  while (zcache != NULL)
    {
      data = zcache->zcache_zfs_data;
      if (data)
      {
        for (i = 0; i < data->n_devices_attached; i++)
          {
            unmount_device (&data->devices_attached[i]);
            grub_free (data->devices_attached[i].children);
          }
        grub_free (data->devices_attached);

        for (i = 0; i < data->subvol.nkeys; i++)
          grub_crypto_cipher_close (data->subvol.keyring[i].cipher);
        grub_free (data->subvol.keyring);

        grub_free (data);
        zcache->zcache_zfs_data = NULL;
      }

      grub_free (zcache->zcache_dev_name);
      zcache->zcache_dev_name = NULL;
      zcache->zcache_dev_id = 0;
 
      zcache_next = zcache->next;
      grub_free (zcache);
      zcache = zcache_next;
    }
  zfs_mount_cache_list = NULL;

  /* free the cache list for disk dev with ZFS uberblock */
  dev_ub = zfs_dev_ublock_list;
  while (dev_ub != NULL)
    {
      grub_free (dev_ub->dev_name);
      dev_ub_next = dev_ub->next;
      grub_free (dev_ub);
      dev_ub = dev_ub_next;
    }
  zfs_dev_ublock_list = NULL;

  /* free the cache list for non-zfs disk dev */
  dev_notzfs = zfs_dev_notzfs_list;
  while (dev_notzfs != NULL)
    {
      grub_free (dev_notzfs->dev_name);
      dev_notzfs_next = dev_notzfs->next;
      grub_free (dev_notzfs);
      dev_notzfs = dev_notzfs_next;
    }
  zfs_dev_notzfs_list = NULL;
}

/*
 * zfs_mount() locates a valid uberblock of the root pool and
 * read in its MOS to the device grub_zfs_data structure.
 *
 * zfs_mount() is called frequently by GRUB2 zfs interfaces, so
 * a cache mechanism is implemented to save the successful zfs
 * mount data for devices. This is good for zfs mount performance.
 *
 */
static struct grub_zfs_data *
zfs_mount (grub_device_t dev)
{
  struct grub_zfs_data *data = 0;
  struct zfs_mount_cache *zcache = 0;
  grub_err_t err;
  objset_phys_t *osp = 0;
  grub_size_t ospsize;
  grub_zfs_endian_t ub_endian = GRUB_ZFS_UNKNOWN_ENDIAN;
  uberblock_t *ub;
  int inserted;
  unsigned int i, j;
  char *diskname, *partname, *fullname;

  if (! dev->disk)
    {
      grub_error (GRUB_ERR_BAD_DEVICE, "not a disk");
      return 0;
    }
 
  diskname = (char *)dev->disk->name;
  partname = grub_partition_get_name(dev->disk->partition);
  if (partname[0] != 0)
    {
      fullname = grub_xasprintf("%s,%s", diskname, partname);
      grub_free (partname);
    }
  else
    fullname = grub_strdup (diskname);

  /* check the zfs mount cache list first */
  for (zcache = zfs_mount_cache_list; zcache != NULL; zcache = zcache->next)
    {
      if (grub_strcmp (fullname, zcache->zcache_dev_name) != 0)
        continue;

      data = zcache->zcache_zfs_data;
      /* use the previous mount data */
      if (data->mount_count == 0)
        {
          /* below items will be re-assigned out of zfs_mount() */
          data->file_buf = 0;
          data->file_start = 0;
          data->file_end = 0;
          data->dnode_buf = 0;
          data->dnode_mdn = 0;
          data->dnode_start = 0;
          data->dnode_end = 0;
          data->dnode_endian = 0;

          /* assign to the new grub device instance */
          if (data->devices_attached)
            {
              struct grub_zfs_device_desc *desc;

              for (i = 0; i < data->n_devices_attached; i++)
                {
                  desc = &data->devices_attached[i];
                  if (desc->original && desc->dev)
                    desc->dev = dev;
                  if (desc->children)
                    {
                      for (j = 0; j < desc->n_children; j++)
                        if (desc->children[j].original && desc->children[j].dev)
                          desc->children[j].dev = dev;
                    }
                }
            }
          if (data->device_original && data->device_original->dev)
            data->device_original->dev = dev;

          data->mount_count++;
          grub_free (fullname);
          return (data);
        }
    }

  /* allocate the zfs mount data structure */
  data = grub_zalloc (sizeof (*data));
  if (! data)
    {
      grub_error (GRUB_ERR_OUT_OF_MEMORY, "zfs data allocation failed");
      grub_free (fullname);
      return 0;
    }

  /* need to do a new mount */
  data->dev_name = fullname;
  data->mount_count++;
  data->n_devices_allocated = 16;
  data->devices_attached = grub_malloc (sizeof (data->devices_attached[0])
					* data->n_devices_allocated);
  data->n_devices_attached = 0;
  err = scan_disk (dev, data, 1, &inserted);
  if (err)
    {
      grub_dprintf("zfs", "scan_disk failed\n");
      grub_free (fullname);
      zfs_unmount (data);
      return NULL;
    }
  grub_dprintf("zfs", "zfs_mount->scan_disk-> #devs = %d\n",
               data->n_devices_attached);
  for (i = 0; i < data->n_devices_attached; i++)
     grub_dprintf("zfs", "devices[%u].dev = %s\n", i,
                  data->devices_attached[i].dev ?
                   data->devices_attached[i].dev->disk->name : "(null)" );

  ub = &(data->current_uberblock);
  ub_endian = (grub_zfs_to_cpu64 (ub->ub_magic, 
				  GRUB_ZFS_LITTLE_ENDIAN) == UBERBLOCK_MAGIC 
	       ? GRUB_ZFS_LITTLE_ENDIAN : GRUB_ZFS_BIG_ENDIAN);

  err = zio_read (&ub->ub_rootbp, ub_endian,
		  (void **) &osp, &ospsize, data);
  if (err)
    {
      grub_dprintf("zfs", "zio_read failed: %s\n", grub_errmsg );
      grub_free (fullname);
      zfs_unmount (data);
      return NULL;
    }

  if (ospsize < OBJSET_PHYS_SIZE_V14)
    {
      grub_error (GRUB_ERR_BAD_FS, "OSP too small");
      grub_free (fullname);
      grub_free (osp);
      zfs_unmount (data);
      return NULL;
    }

  /* Got the MOS. Save it to data->mos. */
  grub_memmove (&(data->mos.dn), &((objset_phys_t *) osp)->os_meta_dnode,
		DNODE_SIZE);
  data->mos.endian = (grub_zfs_to_cpu64 (ub->ub_rootbp.blk_prop,
					 ub_endian) >> 63) & 1;
  grub_free (osp);

  if(ub->ub_version >= SPA_VERSION_FEATURES &&
     check_mos_features(&data->mos, data) != 0)
    {
      grub_free (fullname);
      zfs_unmount (data);
      return NULL;
    }


  data->mounted = 1;	/* mount succeeded */
  if (zcache == NULL)   /* allocate the zfs mount cache structure */
    zcache = grub_zalloc (sizeof (*zcache));   
  else
    zcache = NULL;      /* intend for a non-cached mount */

  if (zcache != NULL)   /* cache this OK zfs mount */
    {
      zcache->zcache_zfs_data = data;
      zcache->zcache_dev_id = dev->disk->id;
      zcache->zcache_dev_name = fullname;
      zcache->next = zfs_mount_cache_list;
      zfs_mount_cache_list = zcache;
      data->zcached = 1;
    }
  else
    {
      grub_free (fullname);
      data->dev_name = NULL;
    }

  return data;
}

grub_err_t
grub_zfs_fetch_nvlist (grub_device_t dev, char **nvlist)
{
  struct grub_zfs_data *zfs;
  grub_err_t err;

  zfs = zfs_mount (dev);
  if (!zfs)
    return grub_errno;
  err = zfs_fetch_nvlist (zfs->device_original, nvlist);
  if (err)
    grub_dprintf("zfs", "zfs_fetch_nvlist failed: #devices=%d type=%d\n",
                 zfs->n_devices_attached, zfs->devices_attached[0].type);
  zfs_unmount (zfs);
  return err;
}

/*
 * Returns the pool name. 
 */
static grub_err_t 
zfs_label (grub_device_t device, char **label)
{
  char *nvlist;
  grub_err_t err;
  struct grub_zfs_data *data;

  *label = NULL;

  data = zfs_mount (device);
  if (! data)
    return grub_errno;

  err = zfs_fetch_nvlist (data->device_original, &nvlist);
  if (err)      
    {
      grub_dprintf("zfs", "zfs_fetch_nvlist failed\n");
      zfs_unmount (data);
      return err;
    }

  *label = grub_zfs_nvlist_lookup_string (nvlist, ZPOOL_CONFIG_POOL_NAME);
  grub_free (nvlist);
  zfs_unmount (data);
  return grub_errno;
}

/*
 * Returns the pool GUID. 
 */
static grub_err_t 
zfs_uuid (grub_device_t device, char **uuid)
{
  struct grub_zfs_data *data;

  *uuid = 0;

  data = zfs_mount (device);
  if (! data)
    return grub_errno;

  *uuid = grub_xasprintf ("%016llx", (long long unsigned) data->guid);
  zfs_unmount (data);
  if (! *uuid)
    return grub_errno;
  return GRUB_ERR_NONE;
}

static grub_err_t 
zfs_mtime (grub_device_t device, grub_int32_t *mt)
{
  struct grub_zfs_data *data;
  grub_zfs_endian_t ub_endian = GRUB_ZFS_UNKNOWN_ENDIAN;
  uberblock_t *ub;

  *mt = 0;

  data = zfs_mount (device);
  if (! data)
    return grub_errno;

  ub = &(data->current_uberblock);
  ub_endian = (grub_zfs_to_cpu64 (ub->ub_magic, 
				  GRUB_ZFS_LITTLE_ENDIAN) == UBERBLOCK_MAGIC 
	       ? GRUB_ZFS_LITTLE_ENDIAN : GRUB_ZFS_BIG_ENDIAN);

  *mt = grub_zfs_to_cpu64 (ub->ub_timestamp, ub_endian);
  zfs_unmount (data);
  return GRUB_ERR_NONE;
}

/*
 * zfs_open() locates a file in the rootpool by following the
 * MOS and places the dnode of the file in the device
 * grub_zfs_data structure.
 */
static grub_err_t
grub_zfs_open (struct grub_file *file, const char *fsfilename)
{
  struct grub_zfs_data *data;
  grub_err_t err;
  int isfs;

  data = zfs_mount (file->device);
  if (! data)
    return grub_errno;

  err = dnode_get_fullpath (fsfilename, &(data->subvol),
			    &(data->dnode), &isfs, data);
  if (err)
    {
      zfs_unmount (data);
      return err;
    }

  if (isfs)
    {
      zfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("missing `%c' symbol"), '@');
    }

  /* We found the dnode for this file. Verify if it is a plain file. */
  if (data->dnode.dn.dn_type != DMU_OT_PLAIN_FILE_CONTENTS) 
    {
      zfs_unmount (data);
      return grub_error (GRUB_ERR_BAD_FILE_TYPE, N_("not a regular file"));
    }

  /* get the file size and set the file position to 0 */

  /*
   * For DMU_OT_SA we will need to locate the SIZE attribute
   * attribute, which could be either in the bonus buffer
   * or the "spill" block.
   */
  if (data->dnode.dn.dn_bonustype == DMU_OT_SA)
    {
      void *sahdrp;
      int hdrsize;

      if (data->dnode.dn.dn_bonuslen != 0)
	{
	  sahdrp = (sa_hdr_phys_t *) DN_BONUS (&data->dnode.dn);
	}
      else if (data->dnode.dn.dn_flags & DNODE_FLAG_SPILL_BLKPTR)
	{
	  blkptr_t *bp = &data->dnode.dn.dn_spill;

	  err = zio_read (bp, data->dnode.endian, &sahdrp, NULL, data);
	  if (err)
	    return err;
	}
      else
	{
	  return grub_error (GRUB_ERR_BAD_FS, "filesystem is corrupt");
	}

      hdrsize = SA_HDR_SIZE (((sa_hdr_phys_t *) sahdrp));
      file->size = grub_zfs_to_cpu64 (grub_get_unaligned64 ((char *) sahdrp + hdrsize + SA_SIZE_OFFSET), data->dnode.endian);
    }
  else if (data->dnode.dn.dn_bonustype == DMU_OT_ZNODE)
    {
      file->size = grub_zfs_to_cpu64 (((znode_phys_t *) DN_BONUS (&data->dnode.dn))->zp_size, data->dnode.endian);
    }
  else
    return grub_error (GRUB_ERR_BAD_FS, "bad bonus type");

  file->data = data;
  file->offset = 0;

#ifndef GRUB_UTIL
  grub_dl_ref (my_mod);
#endif

  return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_zfs_read (grub_file_t file, char *buf, grub_size_t len)
{
  struct grub_zfs_data *data = (struct grub_zfs_data *) file->data;
  grub_size_t blksz, movesize;
  grub_size_t length;
  grub_size_t read;
  grub_err_t err;

  /*
   * If offset is in memory, move it into the buffer provided and return.
   */
  if (file->offset >= data->file_start
      && file->offset + len <= data->file_end)
    {
      grub_memmove (buf, data->file_buf + file->offset - data->file_start,
		    len);
      return len;
    }

  blksz = grub_zfs_to_cpu16 (data->dnode.dn.dn_datablkszsec, 
			     data->dnode.endian) << SPA_MINBLOCKSHIFT;

  if (blksz == 0)
    {
      grub_error (GRUB_ERR_BAD_FS, "0-sized block");
      return -1;
    }

  /*
   * Entire Dnode is too big to fit into the space available.  We
   * will need to read it in chunks.  This could be optimized to
   * read in as large a chunk as there is space available, but for
   * now, this only reads in one data block at a time.
   */
  length = len;
  read = 0;
  while (length)
    {
      void *t;
      /*
       * Find requested blkid and the offset within that block.
       */
      grub_uint64_t blkid = grub_divmod64 (file->offset + read, blksz, 0);
      grub_free (data->file_buf);
      data->file_buf = 0;
      data->file_start = data->file_end = 0;

      err = dmu_read (&(data->dnode), blkid, &t, 0, data);
      data->file_buf = t;
      if (err)
	{
	  data->file_buf = NULL;
	  data->file_start = data->file_end = 0;
	  return -1;
	}

      data->file_start = blkid * blksz;
      data->file_end = data->file_start + blksz;

      movesize = data->file_end - file->offset - read;
      if (movesize > length)
	movesize = length;

      grub_memmove (buf, data->file_buf + file->offset + read
		    - data->file_start, movesize);
      buf += movesize;
      length -= movesize;
      read += movesize;
    }

  return len;
}

static grub_err_t
grub_zfs_close (grub_file_t file)
{
  zfs_unmount ((struct grub_zfs_data *) file->data);

#ifndef GRUB_UTIL
  grub_dl_unref (my_mod);
#endif

  return GRUB_ERR_NONE;
}

grub_err_t
grub_zfs_getmdnobj (grub_device_t dev, const char *fsfilename,
		    grub_uint64_t *mdnobj)
{
  struct grub_zfs_data *data;
  grub_err_t err;
  int isfs;

  data = zfs_mount (dev);
  if (! data)
    return grub_errno;

  err = dnode_get_fullpath (fsfilename, &(data->subvol),
			    &(data->dnode), &isfs, data);
  *mdnobj = data->subvol.obj;
  zfs_unmount (data);
  return err;
}

grub_err_t
grub_zfs_defaultbootfsobj (grub_device_t dev, grub_uint64_t *mdnobj)
{
  struct grub_zfs_data *data;
  grub_err_t err;

  data = zfs_mount (dev);
  if (! data)
    return grub_errno;

  err = get_default_bootfsobj (&(data->mos), mdnobj, data);
  zfs_unmount (data);

  return err;
}

grub_err_t
grub_zfs_defaultbootfsname (grub_device_t dev, char **bootfsname)
{
  grub_uint64_t mdnobj;
  struct grub_zfs_data *data;
  grub_err_t err;

  data = zfs_mount (dev);
  if (! data)
    return grub_errno;

  err = get_default_bootfsobj (&(data->mos), &mdnobj, data);
  if (! err)
    err = get_default_bootfsname(&(data->mos), mdnobj, data, &(*bootfsname));

  zfs_unmount (data);

  return err;
}

static grub_err_t
fill_fs_info (struct grub_dirhook_info *info,
	      dnode_end_t mdn, struct grub_zfs_data *data)
{
  grub_err_t err;
  dnode_end_t dn;
  grub_uint64_t objnum;
  grub_uint64_t headobj;
  
  grub_memset (info, 0, sizeof (*info));
    
  info->dir = 1;
  
  if (mdn.dn.dn_type == DMU_OT_DSL_DIR)
    {
      headobj = grub_zfs_to_cpu64 (((dsl_dir_phys_t *) DN_BONUS (&mdn.dn))->dd_head_dataset_obj, mdn.endian);

      err = dnode_get (&(data->mos), headobj, DMU_OT_DSL_DATASET, &mdn, data);
      if (err)
	{
	  grub_dprintf ("zfs", "failed here\n");
	  return err;
	}
    }
  err = make_mdn (&mdn, data);
  if (err)
    return err;
  err = dnode_get (&mdn, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE, 
		   &dn, data);
  if (err)
    {
      grub_dprintf ("zfs", "failed here\n");
      return err;
    }
  
  err = zap_lookup (&dn, ZFS_ROOT_OBJ, &objnum, data, 0);
  if (err)
    {
      grub_dprintf ("zfs", "failed here\n");
      return err;
    }
  
  err = dnode_get (&mdn, objnum, 0, &dn, data);
  if (err)
    {
      grub_dprintf ("zfs", "failed here\n");
      return err;
    }
  
  if (dn.dn.dn_bonustype == DMU_OT_SA)
    {
      void *sahdrp;
      int hdrsize;

      if (dn.dn.dn_bonuslen != 0)
	{
	  sahdrp = (sa_hdr_phys_t *) DN_BONUS (&dn.dn);
	}
      else if (dn.dn.dn_flags & DNODE_FLAG_SPILL_BLKPTR)
	{
	  blkptr_t *bp = &dn.dn.dn_spill;

	  err = zio_read (bp, dn.endian, &sahdrp, NULL, data);
	  if (err)
	    return err;
	}
      else
	{
	  grub_error (GRUB_ERR_BAD_FS, "filesystem is corrupt");
	  return grub_errno;
	}

      hdrsize = SA_HDR_SIZE (((sa_hdr_phys_t *) sahdrp));
      info->mtimeset = 1;
      info->mtime = grub_zfs_to_cpu64 (grub_get_unaligned64 ((char *) sahdrp + hdrsize + SA_MTIME_OFFSET), dn.endian);
    }

  if (dn.dn.dn_bonustype == DMU_OT_ZNODE)
    {
      info->mtimeset = 1;
      info->mtime = grub_zfs_to_cpu64 (((znode_phys_t *) DN_BONUS (&dn.dn))->zp_mtime[0], dn.endian);
    }
  return 0;
}

/* Helper for grub_zfs_dir.  */
static int
iterate_zap (const char *name, grub_uint64_t val, struct grub_zfs_dir_ctx *ctx)
{
  grub_err_t err;
  struct grub_dirhook_info info;

  dnode_end_t dn;
  grub_memset (&info, 0, sizeof (info));

  err = dnode_get (&(ctx->data->subvol.mdn), val, 0, &dn, ctx->data);
  if (err)
    {
      grub_print_error ();
      return 0;
    }

  if (dn.dn.dn_bonustype == DMU_OT_SA)
    {
      void *sahdrp;
      int hdrsize;

      if (dn.dn.dn_bonuslen != 0)
	{
	  sahdrp = (sa_hdr_phys_t *) DN_BONUS (&ctx->data->dnode.dn);
	}
      else if (dn.dn.dn_flags & DNODE_FLAG_SPILL_BLKPTR)
	{
	  blkptr_t *bp = &dn.dn.dn_spill;

	  err = zio_read(bp, dn.endian, &sahdrp, NULL, ctx->data);
	  if (err)
	    {
	      grub_print_error();
	      return 0;
	    }
	}
      else
        {
	  grub_error(GRUB_ERR_BAD_FS, "filesystem is corrupt");
	  grub_print_error();
	  return 0;
	}

      hdrsize = SA_HDR_SIZE (((sa_hdr_phys_t *) sahdrp));
      info.mtimeset = 1;
      info.mtime = grub_zfs_to_cpu64(grub_get_unaligned64((char *) sahdrp + hdrsize + SA_MTIME_OFFSET), dn.endian);
      info.case_insensitive = ctx->data->subvol.case_insensitive;
    }

  if (dn.dn.dn_bonustype == DMU_OT_ZNODE)
    {	
      info.mtimeset = 1;
      info.mtime = grub_zfs_to_cpu64(((znode_phys_t *) DN_BONUS (&dn.dn))->zp_mtime[0],
				     dn.endian);
    }
  info.dir = (dn.dn.dn_type == DMU_OT_DIRECTORY_CONTENTS);
  grub_dprintf ("zfs", "type=%d, name=%s\n", 
		(int)dn.dn.dn_type, (char *)name);
  return ctx->hook(name, &info, ctx->hook_data);
}

/* Helper for grub_zfs_dir.  */
static int
iterate_zap_fs(const char *name, grub_uint64_t val,
    struct grub_zfs_dir_ctx *ctx)
{
	grub_err_t err;
	struct grub_dirhook_info info;
	dnode_end_t mdn;
	err = dnode_get (&(ctx->data->mos), val, 0, &mdn, ctx->data);
	if (err) {
		grub_errno = 0;
		return 0;
	}
	if (mdn.dn.dn_type != DMU_OT_DSL_DIR)
		return 0;

	err = fill_fs_info (&info, mdn, ctx->data);
	if (err) {
		grub_errno = 0;
		return 0;
	}
	return ctx->hook (name, &info, ctx->hook_data);
}

/* Helper for grub_zfs_dir.  */
static int
iterate_zap_snap(const char *name, grub_uint64_t val,
    struct grub_zfs_dir_ctx *ctx)
{
	grub_err_t err;
	struct grub_dirhook_info info;
	char *name2;
	int ret;
	dnode_end_t mdn;

	err = dnode_get(&(ctx->data->mos), val, 0, &mdn, ctx->data);
	if (err) {
		grub_errno = 0;
		return 0;
	}

	if (mdn.dn.dn_type != DMU_OT_DSL_DATASET)
		return 0;

	err = fill_fs_info(&info, mdn, ctx->data);
	if (err) {
		grub_errno = 0;
		return 0;
	}

	name2 = grub_malloc(grub_strlen (name) + 2);
	name2[0] = '@';
	grub_memcpy(name2 + 1, name, grub_strlen (name) + 1);
	ret = ctx->hook(name2, &info, ctx->hook_data);
	grub_free(name2);
	return ret;
}

static grub_err_t
grub_zfs_dir (grub_device_t device, const char *path,
	      grub_fs_dir_hook_t hook, void *hook_data)
{
	struct grub_zfs_dir_ctx ctx = {
		.hook = hook,
		.hook_data = hook_data
	};
	struct grub_zfs_data *data;
	grub_err_t err;
	int isfs;

	data = zfs_mount(device);
	if (!data)
		return grub_errno;
	err = dnode_get_fullpath(path, &(data->subvol), &(data->dnode),
	    &isfs, data);
	if (err) {
		grub_dprintf("zfs", "dnode_get_fullpath failed\n");
		zfs_unmount(data);
		return err;
	}
	ctx.data = data;

	if (isfs) {
		grub_uint64_t childobj, headobj; 
		grub_uint64_t snapobj;
		dnode_end_t dn;
		struct grub_dirhook_info info;

		err = fill_fs_info(&info, data->dnode, data);
		if (err) {
			zfs_unmount(data);
			return err;
		}
		if (hook ("@", &info, hook_data)) {
			zfs_unmount(data);
			return GRUB_ERR_NONE;
		}
      
		childobj = grub_zfs_to_cpu64(
		    ((dsl_dir_phys_t *)
		    DN_BONUS (&data->dnode.dn))->dd_child_dir_zapobj,
		    data->dnode.endian);

		headobj = grub_zfs_to_cpu64(
		    ((dsl_dir_phys_t *)
		    DN_BONUS (&data->dnode.dn))->dd_head_dataset_obj,
		    data->dnode.endian);
		err = dnode_get (&(data->mos), childobj,
		    DMU_OT_DSL_DIR_CHILD_MAP, &dn, data);
		if (err) {
			zfs_unmount(data);
			return err;
		}

		zap_iterate_u64(&dn, iterate_zap_fs, data, &ctx);
      
		err = dnode_get(&(data->mos), headobj,
		    DMU_OT_DSL_DATASET, &dn, data);
		if (err) {
			zfs_unmount(data);
			return err;
		}

		snapobj = grub_zfs_to_cpu64(
		    ((dsl_dataset_phys_t *)
		    DN_BONUS (&dn.dn))->ds_snapnames_zapobj, dn.endian);

		err = dnode_get(&(data->mos), snapobj,
		    DMU_OT_DSL_DS_SNAP_MAP, &dn, data);
		if (err) {
			zfs_unmount(data);
			return err;
		}

		zap_iterate_u64(&dn, iterate_zap_snap, data, &ctx);
	} else {
		if (data->dnode.dn.dn_type != DMU_OT_DIRECTORY_CONTENTS) {
			zfs_unmount (data);
			return grub_error(GRUB_ERR_BAD_FILE_TYPE,
			    N_("not a directory"));
		}
		zap_iterate_u64(&(data->dnode), iterate_zap, data, &ctx);
	}
	zfs_unmount(data);
	return grub_errno;
}

#ifdef GRUB_UTIL
static grub_err_t
grub_zfs_embed (grub_device_t device __attribute__ ((unused)),
		unsigned int *nsectors,
		unsigned int max_nsectors,
		grub_embed_type_t embed_type,
		grub_disk_addr_t **sectors)
{
  unsigned i;

  if (embed_type != GRUB_EMBED_PCBIOS)
    return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
		       "ZFS currently supports only PC-BIOS embedding");

  if ((VDEV_BOOT_SIZE >> GRUB_DISK_SECTOR_BITS) < *nsectors)
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
		       N_("your core.img is unusually large.  "
			  "It won't fit in the embedding area"));

  *nsectors = (VDEV_BOOT_SIZE >> GRUB_DISK_SECTOR_BITS);
  if (*nsectors > max_nsectors)
    *nsectors = max_nsectors;
  *sectors = grub_malloc (*nsectors * sizeof (**sectors));
  if (!*sectors)
    return grub_errno;
  for (i = 0; i < *nsectors; i++)
    (*sectors)[i] = i + (VDEV_BOOT_OFFSET >> GRUB_DISK_SECTOR_BITS);

  return GRUB_ERR_NONE;
}
#endif

/* GRUB2 zfs FS module interface structure */
static struct grub_fs grub_zfs_fs = {
  .name = "zfs",
  .dir = grub_zfs_dir,
  .open = grub_zfs_open,
  .read = grub_zfs_read,
  .close = grub_zfs_close,
  .label = zfs_label,
  .uuid = zfs_uuid,
  .mtime = zfs_mtime,
#ifdef GRUB_UTIL
  .embed = grub_zfs_embed,
  .reserved_first_sector = 1,
#endif
  .next = 0
};

GRUB_MOD_INIT (zfs)
{
  COMPILE_TIME_ASSERT (sizeof (zap_leaf_chunk_t) == ZAP_LEAF_CHUNKSIZE);
  grub_fs_register (&grub_zfs_fs);
#ifndef GRUB_UTIL
  my_mod = mod;
#endif
}

GRUB_MOD_FINI (zfs)
{
  zfs_free_caches ();
  grub_fs_unregister (&grub_zfs_fs);
}
