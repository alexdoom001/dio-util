#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <getopt.h>

/*****************************************************************************/
#define SBOX_NAME      "uz.db3"
#define BKEY_NAME      "gk.db3"
#define PCKT_NAME      "km_k/kis_1"
#define PATH_SEPARATOR "/"

/*****************************************************************************/
#define step(tmp, half) \
        (half ^= cache[tmp & 0xff] ^                 \
                 cache[256 + ((tmp >> 8) & 0xff)] ^  \
                 cache[512 + ((tmp >> 16) & 0xff)] ^ \
                 cache[768 + ((tmp >> 24))])

/*****************************************************************************/
#define round8(tmp, half1, half2, k1, k2, k3, k4, k5, k6, k7, k8) \
        do {                                 \
                tmp = k1 + half1;            \
                tmp = k2 + step(tmp, half2); \
                tmp = k3 + step(tmp, half1); \
                tmp = k4 + step(tmp, half2); \
                tmp = k5 + step(tmp, half1); \
                tmp = k6 + step(tmp, half2); \
                tmp = k7 + step(tmp, half1); \
                tmp = k8 + step(tmp, half2); \
                step(tmp, half1);            \
        } while(false);

/*****************************************************************************/
enum { FORW = 1, BACK = 2 }; /** SA/SP direction flags */

/*****************************************************************************/
typedef struct key_mac /** Key and its lightweight hash */
{
	uint32_t key[8]; /** Key */
	uint32_t mac;    /** Key lightweight hash */

} key_mac_t;

/*****************************************************************************/
typedef struct pckt /** Table of network keys */
{
	uint32_t  serial; /**< Serial number   */
	uint16_t  self;   /**< Self number     */
	uint16_t  n;      /**< Number of items */
	key_mac_t x[];    /**< Items           */

} pckt_t;

/*****************************************************************************/
char const *sbox_name = NULL; /** S-Box full filename */
char const *bkey_name = NULL; /** Base Key full filename */
char const *pckt_name = NULL; /** Pair Connection Key Table full filename */

/*****************************************************************************/
uint32_t cache[1024]; /** The cache for S-Box */

/*****************************************************************************/
uint8_t  sbox[64] = { 0 }; /** S-box itself */
uint32_t bkey[8]  = { 0 }; /** Base Key itself */

/*****************************************************************************/
pckt_t *pckt = NULL; /** Pair Connection Key Table (PCKT) itself */

/*****************************************************************************/
/* Encipher-16 base cycle */
static void dio_ebc_16(uint64_t *X, uint32_t const k[8], uint32_t const cache[1024])
{
	uint32_t a = (uint32_t)(*X >> 32);
	uint32_t b = (uint32_t)(*X);
	register uint32_t        tmp;
	round8(tmp, b, a, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]);
	round8(tmp, b, a, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]);
	*X = (uint64_t)a << 32 | b;
}

/*****************************************************************************/
/* Convert 16-bit value from little endian to CPU representation */
static uint16_t le16_to_cpu(uint16_t x)
{
	uint16_t       y = 0;
	uint8_t const *p = (uint8_t const *) & x + sizeof x - 1;
	unsigned int   u;

	for (u = 0; u < sizeof x; u++)
		y = 256 * y + *p--;

	return y;
}

/*****************************************************************************/
/* Convert 32-bit value from little endian to CPU representation */
static uint32_t le32_to_cpu(uint32_t x)
{
	uint32_t       y = 0;
	uint8_t const *p = (uint8_t const *) & x + sizeof x - 1;
	unsigned int   u;

	for (u = 0; u < sizeof x; u++)
		y = 256 * y + *p--;

	return y;
}

/*****************************************************************************/
/* Convert 64-bit value from little endian to CPU representation */
static uint64_t le64_to_cpu(uint64_t x)
{
	uint64_t       y = 0;
	uint8_t const *p = (uint8_t const *) & x + sizeof x - 1;
	unsigned int   u;

	for (u = 0; u < sizeof x; u++)
		y = 256 * y + *p--;

	return y;
}

/*****************************************************************************/
/* Convert 32-bit value from CPU to little endian representation */
static uint32_t cpu_to_le32(uint32_t x)
{
	uint32_t y = 0;
	uint8_t *p = (uint8_t *) & y;

	for (; x != 0; x /= 256)
		* p++ = x % 256;

	return y;
}

/*****************************************************************************/
/* Compute lightweight hash for a key (src) on a key (key) */
static void dio_get_key_mac(uint32_t *mac, uint32_t const src[8],
			    uint32_t const key[8], uint32_t const cache[1024])
{
	uint64_t              X   = 0;
	uint64_t const       *s   = (uint64_t const *)src;
	uint64_t const *const end = s + sizeof bkey / sizeof s[0];

	while (s < end)
	{
		X ^= le64_to_cpu(*s++);
		dio_ebc_16(&X, key, cache);
	}

	*mac = (uint32_t)X;
	X = 0;
}

/*****************************************************************************/
/* Decipher-32 base cycle */
static void dio_dbc_32(uint32_t *dst, uint32_t const *src,
		       uint32_t const k[8], uint32_t const uc[1024])
{
	uint32_t const   *s = (uint32_t const *)src;
	uint32_t         *d = (uint32_t *)dst;
	register uint32_t a = le32_to_cpu(s[1]);
	register uint32_t b = le32_to_cpu(s[0]);
	register uint32_t tmp;
	round8(tmp, b, a, k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]);
	round8(tmp, b, a, k[7], k[6], k[5], k[4], k[3], k[2], k[1], k[0]);
	round8(tmp, b, a, k[7], k[6], k[5], k[4], k[3], k[2], k[1], k[0]);
	round8(tmp, b, a, k[7], k[6], k[5], k[4], k[3], k[2], k[1], k[0]);
	d[1] = cpu_to_le32(b);
	d[0] = cpu_to_le32(a);
}

/*****************************************************************************/
/* Decipher a key (src) on a key(key) */
static void dio_decode_key(uint32_t dst[8], uint32_t const src[8],
			   uint32_t const key[8], uint32_t const cache[1024])
{
	unsigned int u;

	for (u = 0; u < sizeof bkey / sizeof bkey[0]; u += 2)
		dio_dbc_32(&dst[u], &src[u], key, cache);
}

/*****************************************************************************/
/* Generate S-Box cache */
static void dio_gen_sbox_cache(uint32_t cache[1024], uint8_t const sbox[64])
{
	unsigned int i;

	for (i = 0; i < 16; i++)
	{
		unsigned int j;

		for (j = 0; j < 16; j++)
		{
			unsigned int k;

			for (k = 0; k < 4; k++)
			{
				uint8_t    n = (11 + 8 * k) % 32;
				uint32_t tmp = (((uint8_t *)sbox)[4 * i + k] & 0xf0) |
					       (((uint8_t *)sbox)[4 * j + k] & 0x0f);
				cache[256 * k + 16 * i + j] = tmp << n | tmp >> (32 - n);
			}
		}
	}
}

/*****************************************************************************/
/* Executive part for 'dio_unmask()' function */
static int dio_unmask_executive(void const *from, unsigned int size,
				void *to, unsigned int len)
{
	uint8_t const *src = from;
	uint8_t       *dst = to;
	unsigned int m = *src++ & 0xf0;
	unsigned int n = *src++;
	unsigned int i;

	if (m != size || n * m + 4 > len)
		return -1;

	memcpy(dst, src, m + 4);
	dst += 4;

	while (--n > 0)
		for (i = 0; i < m; i++)
			dst[i] ^= *src++;

	return 0;
}

/*****************************************************************************/
/* Perform unmasking for just read S-Box or Base Key */
static int dio_unmask(void const *from, unsigned int size,
		      void *to, unsigned int len)
{
	if (len < 22)
		return -1;

	return dio_unmask_executive(from, size, to, len);
}

/*****************************************************************************/
/* Get file length by handle */
static long get_file_len(FILE *f)
{
	long len = -1;
	long cur = ftell(f);

	if (cur == -1 || fseek(f, 0, SEEK_END) == -1)
		return -1;

	len = ftell(f);

	if (fseek(f, cur, SEEK_SET) == -1)
		return -1;

	return len;
}

/*****************************************************************************/
/* Read S-Box from a file, unmask it and generate the cache for it */
static int get_sbox(FILE *f)
{
	uint8_t buf[1024];
	uint8_t tmp[4 + sizeof sbox];
	long    len = get_file_len(f);

	if (len < 0 || len > sizeof buf)
	{
		fprintf(stderr, "%s: Invalid S-Box file\n", sbox_name);
		return -1;
	}

	if (fread(buf, 1, sizeof buf, f) != len)
	{
		fprintf(stderr, "%s: Cannot read %li bytes\n", sbox_name, len);
		return -1;
	}

	if (*buf != 0x40 || dio_unmask(buf, sizeof sbox, tmp, len) == -1)
	{
		fprintf(stderr, "%s: Invalid S-Box file\n", sbox_name);
		return -1;
	}

	memcpy(sbox, tmp + 4, sizeof sbox);
	dio_gen_sbox_cache(cache, sbox);
	return 0;
}

/*****************************************************************************/
/* Read a password from the current tty */
char const *get_pwd(void)
{
	/* FIXME: Should be implemented!!! */
	return "ho-ho";
}

/*****************************************************************************/
/* Calculate password hash (private selfmade algorithm is used) */
static void get_pwd_hash(uint8_t dst[32], char const *pwd)
{
	uint8_t *c;
	uint8_t *v;
	uint8_t p[38] = { 0 };
	int i;
	int j;
	size_t l = strlen(pwd);

	if (l == 0 || l > 36)
	{
		memset(dst, 0, 32);
		return;
	}

	memcpy(p, pwd, l);

	for (j = 0; j < 37 - l; j++)
		p[j + l] = p[j];

	c = p + 32;
	v = p;

	for (i = 0; i < 5; i++, c++)
		for (j = 0; j < 7; j++, v++)
		{
			*v = (*v << 1) | (*c & 1);
			*c >>= 1;
		}

	memcpy(dst, p, 32);
}

/*****************************************************************************/
/* Decrypt Base Key on a key of password hash */
static int get_pwd_decode_bkey(void)
{
	char const *pwd = get_pwd();
	uint32_t    key[8];

	if (pwd == NULL)
		return -1;

	get_pwd_hash((uint8_t *)key, pwd);
	dio_decode_key(bkey, bkey, key, cache);
	return 0;
}

/*****************************************************************************/
/* Read Base Key from a file and get it in the plain form */
static int get_bkey(FILE *f)
{
	uint8_t  buf[1024];
	uint8_t  tmp[4 + sizeof sbox];
	long     len = get_file_len(f);
	uint32_t zero[sizeof bkey / sizeof bkey[0]] = { 0 };
	uint32_t mac;
	uint32_t calculated_mac;

	if (len < 0 || len > sizeof buf)
	{
		fprintf(stderr, "%s: Invalid Base Key file\n", bkey_name);
		return -1;
	}

	if (fread(buf, 1, sizeof buf, f) != len)
	{
		fprintf(stderr, "%s: Cannot read %li bytes\n", bkey_name, len);
		return -1;
	}

	if ((*buf & ~1) != 0x20 || dio_unmask(buf, sizeof bkey, tmp, len) == -1)
	{
		fprintf(stderr, "%s: Invalid Base Key file\n", bkey_name);
		return -1;
	}

	memcpy(bkey, tmp + 4, sizeof bkey);
	memcpy(&mac, tmp, sizeof mac);
	mac = le32_to_cpu(mac);

	if (*buf == 0x20 && get_pwd_decode_bkey() == -1)
	{
		fprintf(stderr, "%s: Invalid password\n", bkey_name);
		return -1;
	}

	dio_get_key_mac(&calculated_mac, zero, bkey, cache);

	if (mac != calculated_mac)
	{
		fprintf(stderr, "%s: Wrong password\n", bkey_name);
		return -1;
	}

	return 0;
}

/*****************************************************************************/
/* Read PCKT from a file */
static int get_pckt(FILE *f)
{
	static uint8_t const C1[] =
	{
		0x6d, 0x01, 0x6f, 0xf6, 0x13, 0xfc, 0x52, 0x99,
		0xa2, 0x79, 0x7e, 0xfc, 0xcd, 0xcd, 0x68, 0x40,
		0xf6, 0x74, 0x5e, 0x7d, 0xb4, 0xc7, 0x62, 0x7b,
		0xff, 0x3e, 0x38, 0x46, 0x38, 0xfb, 0x3a, 0x5c
	};
	uint32_t const *C32 = (uint32_t const *)C1;
	long            len = get_file_len(f);
	key_mac_t       key_mac;
	unsigned int    u;
	pckt_t          hdr;

	if (len < 0)
	{
		fprintf(stderr, "%s: Invalid PCKT file\n", pckt_name);
		return -1;
	}

	if (fread(&hdr, 1, sizeof hdr, f) != sizeof hdr)
	{
		fprintf(stderr, "%s: Cannot read %li bytes\n", pckt_name, sizeof hdr);
		return -1;
	}

	if ((pckt = malloc(sizeof pckt + hdr.n * sizeof hdr.x[0])) == NULL)
	{
		errno = ENOMEM;
		perror(__FUNCTION__);
		return -1;
	}

	memcpy(pckt, &hdr, sizeof hdr);
	hdr.serial = le32_to_cpu(hdr.serial);
	hdr.self   = le16_to_cpu(hdr.self);
	hdr.n      = le16_to_cpu(hdr.n);

	if (fread(pckt->x, sizeof hdr.x[0], hdr.n, f) != hdr.n)
	{
		fprintf(stderr, "%s: Cannot read %li bytes\n", pckt_name, sizeof hdr.x[0] * hdr.n);
		return -1;
	}

	for (u = 0; u < hdr.n; u++)
	{
		key_mac.mac = le32_to_cpu(key_mac.mac);
		dio_decode_key(key_mac.key, pckt->x[u].key, bkey, cache);
		dio_get_key_mac(&key_mac.mac, key_mac.key, bkey, cache);

		if (pckt->x[u].mac != key_mac.mac)
		{
			fprintf(stderr, "%s: Key #%u is corrupted\n", pckt_name, u + 1);
			return -1;
		}

		dio_decode_key(pckt->x[u].key, C32, key_mac.key, cache);
	}

	return 0;
}

/*****************************************************************************/
/* Read and convert into the plain form Base Key, S-Box or PCKT */
static int init_key(char const *name, int (*pf)(FILE *))
{
	int   rc = 0;
	FILE *f  = fopen(name, "r");

	if (f == NULL)
	{
		perror(name);
		return -1;
	}

	rc = (*pf)(f);
	fclose(f);
	return rc;
}

/*****************************************************************************/
/* Perform Base Key, S-Box and PCKT reading and converting */
static int init_keys(void)
{
	if (init_key(sbox_name, &get_sbox) == -1 ||
	    init_key(bkey_name, &get_bkey) == -1 ||
	    init_key(pckt_name, &get_pckt) == -1)
	{
		return -1;
	}

	return 0;
}

/*****************************************************************************/
/* Free resources taken for Base Key, S-Box and PCKT reading and converting */
static void fini_keys(void)
{
	free(pckt);
	pckt = NULL;
}

/*****************************************************************************/
/* Comprise the full name basing on a path and a file name */
char const *get_path_name(char const *path, char const *name)
{
	size_t path_len = strlen(path);
	size_t psep_len = strlen(PATH_SEPARATOR);
	size_t name_len = strlen(name);
	char  *p        = malloc(path_len + psep_len + name_len + 1);

	if (p != NULL)
	{
		memcpy(p, path, path_len);
		memcpy(p + path_len, PATH_SEPARATOR, psep_len);
		memcpy(p + path_len + psep_len, name, name_len + 1);
	}

	return p;
}

/*****************************************************************************/
/* Form all needed full names */
static int init_paths(char const *path)
{
	if ((sbox_name = get_path_name(path, SBOX_NAME)) != NULL)
	{
		if ((bkey_name = get_path_name(path, BKEY_NAME)) != NULL)
		{
			if ((pckt_name = get_path_name(path, PCKT_NAME)) != NULL)
				return 0;

			free((void *)bkey_name);
			bkey_name = NULL;
		}

		free((void *)sbox_name);
		sbox_name = NULL;
	}

	errno = ENOMEM;
	perror(__FUNCTION__);
	return -1;
}

/*****************************************************************************/
/* Free resources taken for all needed full names */
static void fini_paths(void)
{
	free((void *)pckt_name);
	pckt_name = NULL;
	free((void *)bkey_name);
	bkey_name = NULL;
	free((void *)sbox_name);
	sbox_name = NULL;
}

/*****************************************************************************/
/* Convert binary string into its hexadecimal representation */
static int get_hex_string(char *b, size_t l, uint32_t const *val, size_t len)
{
	static char xlat[] = { '0', '1', '2', '3', '4', '5', '6', '7',
			       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
			     };
	unsigned int   u;
	uint8_t const *v = (uint8_t const *)val;

	if (l < 2 + len * 2 + 1)
		return -1;

	*b++ = '0';
	*b++ = 'x';

	for (u = 0; u < len; u++)
	{
		uint8_t x = v[u];
		*b++ = xlat[x / 16];
		*b++ = xlat[x % 16];
	}

	*b = '\0';
	return 0;
}

/*****************************************************************************/
static int print_key(uint16_t r)
{
	char  k[2 + 2 * sizeof pckt->x[r].key + 1];
	
	if (r == 0 || r > pckt->n)
		return -1;
	if (get_hex_string(k, sizeof k, pckt->x[r - 1].key,
	                   sizeof pckt->x[r - 1].key) == -1) {
		return -1;
	}
	printf("KEY[%i]:\t%s\n", r, k);
	return 0;
}

static int print_keys()
{
	uint16_t r;
	
	for (r = 1; r <= pckt->n; ++r) {
		if (print_key(r) != 0) return -1;
	}
	return 0;
}

static int print_sbox()
{
	char  sb[2 + 2 * sizeof sbox + 1];
	
	if (get_hex_string(sb, sizeof sb,
	                   (uint32_t const *)sbox, sizeof sbox) == -1) {
		return -1;
	}
	printf("SBOX:\t%s\n", sb);
	return 0;
}

/*****************************************************************************/
/* No comments */
static void usage(char const *name)
{
	printf("\nUsage: %s [options] path_to_keys\n"
	       "\n"
	       "  -s --sbox    none         print sbox\n"
	       "  -k --key     $cn|all|own  print gost key with given cryptonumber\n"
	       "                              all - print all keys\n"
	       "                              own - print own key\n"
	       "  -S --serial  none         print keys serial\n"
	       "  -O --own-cn  none         print own cryptonumber\n"
	       "  -N --numkeys none         print quantity of keys in serial\n"
	       "\n"
	       "\n"
	       , name);
}

int main(int argc, char **argv)
{
#define IS_KEY_ALL -1
#define IS_KEY_OWN -2
	int is_sbox = 0;
	int is_key = 0;
	int is_serial = 0;
	int is_own_cn = 0;
	int is_numkeys = 0;
	
	struct option long_options[] =
	{
		{ "sbox"                , 0, NULL, 0 },
		{ "key"                 , 1, NULL, 0 },
		{ "serial"              , 0, NULL, 0 },
		{ "own-cn"              , 0, NULL, 0 },
		{ "numkeys"             , 0, NULL, 0 },
		{ NULL                  , 0, NULL, 0 }
	};
	char const  xlat[]           =
		{ 's',
		  'k',
		  'S',
		  'O',
		  'N'
		};

	for (;;)
	{
		int option_index   = -1;
		int c = getopt_long(argc, argv, "sk:SON", long_options, &option_index);
		char option_name[] = { c, '\0' };
		char const *p = option_name;

		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				/* Provide unified further processing */
				p = long_options[option_index].name;
				c = xlat[option_index];
			case 's':
			case 'k':
			case 'S':
			case 'O':
			case 'N':

				/* The case when a long option is specified with a single (instead of double) dash */
				if (optarg && *optarg == '-')
				{
					fprintf(stderr, "%s: option `-%s%s' requires an argument\n", *argv, p == option_name ? "" : "-", p);
					return 2;
				}
		}
		
		switch (c)
		{
			case 's':
				is_sbox = 1;
				break;
			case 'k':
				if (optarg == NULL) {
					fprintf(stderr, "to get key provide it crypto number\n");
					return 1;
				}
				if (!strcmp(optarg, "all")) is_key = IS_KEY_ALL;
				else if (!strcmp(optarg, "own")) is_key = IS_KEY_OWN;
				else is_key = atoi(optarg);
				break;
			case 'S':
				is_serial = 1;
				break;
			case 'O':
				is_own_cn = 1;
				break;
			case 'N':
				is_numkeys = 1;
				break;
			case '?':
				return 2;
			default:
				fprintf(stderr, "%s: Internal error\n", *argv);
				return 1;
		}
	}
	
	/* Number of unprocessed non-option arguments */
	switch (argc - optind)
	{
			/* No non-option arguments specified */
		case 0:
			fprintf(stderr, "%s: No path_to_keys is specified\n", *argv);
			usage(argv[0]);
			return 1;
			/* Exactly 1 argument is specified */
		case 1:
			break;
			/* More than 1 arguments are specified */
		default:
			fprintf(stderr, "%s: Path_to_keys is specified more than one time:\n", *argv);
			usage(argv[0]);
			return 1;
	}
	
	if (init_paths(argv[optind]) == 0)
	{
		/* Read Base Key, S-Box and PCKT from files and convert into the plain form */
		if (init_keys() == 0)
		{
			if (is_sbox) print_sbox();
			if (is_key == IS_KEY_ALL) print_keys();
			else if (is_key == IS_KEY_OWN) print_key(pckt->self);
			else if (is_key > 0) print_key(is_key);
			if (is_serial) printf("SERIAL:\t%u\n", pckt->serial);
			if (is_own_cn) printf("OWN_CN:\t%u\n", pckt->self);
			if (is_numkeys) printf("NUMKEYS:\t%u\n", pckt->n);
			/* Free resources taken by Base Key, S-Box and PCKT */
			fini_keys();
		} else {
			fprintf(stderr, "can't initialize keys\n");
			return 1;
		}

		/* Free resources taken by full names */
		fini_paths();
	} else {
		fprintf(stderr, "can't initialize paths\n");
		return 1;
	}
	return 0;
}