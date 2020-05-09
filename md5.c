//
// Created by kitos on 05.05.2020.
//

#include "ft_ssl.h"

static const uint32_t g_s[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17,
	22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16,
	23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15,
	21, 6, 10, 15, 21, 6, 10, 15, 21
};

static const uint32_t g_K[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static void	fill_basic_value(void)
{
	g_ssl->a0 = 0x67452301;
	g_ssl->b0 = 0xefcdab89;
	g_ssl->c0 = 0x98badcfe;
	g_ssl->d0 = 0x10325476;
}

static	void	ft_create_stream_date(char *slovo, int len)
{
	fill_basic_value();
	g_ssl->len = len + 1;
	while (g_ssl->len % 64 != 56)
		g_ssl->len++;
	g_ssl->bufer = (char *)malloc(sizeof(char) * (g_ssl->len + 64));
	ft_bzero(g_ssl->bufer, g_ssl->len + 64);
	ft_strcpy(g_ssl->bufer, slovo);
	*(uint32_t *)(g_ssl->bufer + len) = 0x80;
	*(uint32_t *)(g_ssl->bufer + g_ssl->len) = (uint32_t)(len * 8);
}

static	void	ft_work_hourse_md5(int i, int g)
{
	if (i < 16)
	{
		g_ssl->F = F(g_ssl->B, g_ssl->C, g_ssl->D);
		g = i;
	}
	else if (i < 32)
	{
		g_ssl->F = G(g_ssl->B, g_ssl->C, g_ssl->D);
		g = (5*i + 1)%16;
	}
	else if (i < 48)
	{
		g_ssl->F = H(g_ssl->B, g_ssl->C, g_ssl->D);
		g = (3*i + 5) % 16;
	}
	else
	{
		g_ssl->F = I(g_ssl->B, g_ssl->C, g_ssl->D);
		g = (7*i) % 16;
	}
	g_ssl->F = g_ssl->F + g_ssl->A + g_K[i] + g_ssl->t[g];
	g_ssl->A = g_ssl->D;
	g_ssl->D = g_ssl->C;
	g_ssl->C = g_ssl->B;
	g_ssl->B = g_ssl->B + leftrotate(g_ssl->F, g_s[i]);
}

void	ft_md5(char *slovo, int len)
{
	int	i;
	int j;

	i = 0;
	ft_create_stream_date(slovo, len);
	while (g_ssl->len > i)
	{
		j = 0;
		g_ssl->t = (uint32_t *)g_ssl->bufer + i;
		g_ssl->A = g_ssl->a0;
		g_ssl->B = g_ssl->b0;
		g_ssl->C = g_ssl->c0;
		g_ssl->D = g_ssl->d0;
		g_ssl->F = 0;
		while (j < 64)
			ft_work_hourse_md5(j++, 0);
		g_ssl->a0 = g_ssl->a0 + g_ssl->A;
		g_ssl->b0 = g_ssl->b0 + g_ssl->B;
		g_ssl->c0 = g_ssl->c0 + g_ssl->C;
		g_ssl->d0 = g_ssl->d0 + g_ssl->D;
		i += 64;
	}
	ft_strdel(&(g_ssl->bufer));
	g_ssl->bufer = NULL;
	g_ssl->t = NULL;
}