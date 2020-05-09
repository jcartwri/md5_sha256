//
// Created by kitos on 07.05.2020.
//

#include "ft_ssl.h"

static const uint32_t g_K[] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static void	fill_basic_value(void)
{
	g_ssl->h0 = 0x6a09e667;
	g_ssl->h1 = 0xbb67ae85;
	g_ssl->h2 = 0x3c6ef372;
	g_ssl->h3 = 0xa54ff53a;
	g_ssl->h4 = 0x510e527f;
	g_ssl->h5 = 0x9b05688c;
	g_ssl->h6 = 0x1f83d9ab;
	g_ssl->h7 = 0x5be0cd19;
}

//static	void	ft_create_stream_date(char *slovo, int len)
//{
//	int	i;
//
//	fill_basic_value();
//	g_ssl->len = len * 8 + 1;
//	while (g_ssl->len % 512 != 448)
//		g_ssl->len++;
//	g_ssl->bufer_32 = (uint32_t *)malloc(sizeof(uint32_t) * ((g_ssl->len + 64) / 8));
//	ft_bzero(g_ssl->bufer_32, (g_ssl->len + 64) / 8);
//	ft_memcpy((char *)g_ssl->bufer_32, slovo, len);
//	((char *)g_ssl->bufer_32)[len] = 0x80;
//	i = 0;
//	while (i < (g_ssl->len + 64) / 64)
//	{
//		g_ssl->bufer_32[i] = revers_uint32(g_ssl->bufer_32[i]);
//		i++;
//	}
//	g_ssl->bufer_32[g_ssl->len / 32 + 1] = len;
//}

static void ft_create_stream_date(char *slovo, int len)
{
	int i;

	fill_basic_value();
	g_ssl->len = len * 8;
	g_ssl->col_block = 1 + ((g_ssl->len + 1 + 64) / 512);
	g_ssl->bufer_32 = malloc(16 * g_ssl->col_block * 4);
	ft_bzero(g_ssl->bufer_32, 16 * g_ssl->col_block * 4);
	ft_memcpy((char *)g_ssl->bufer_32, slovo, len);
	((char *)g_ssl->bufer_32)[ft_strlen(slovo)] = 0x80;
	i = 0;
	while (i < (g_ssl->col_block * 16) - 1)
	{
		g_ssl->bufer_32[i] = revers_uint32(g_ssl->bufer_32[i]);
		i++;
	}
	g_ssl->bufer_32[((g_ssl->col_block * 512 - 64) / 32) + 1] = g_ssl->len;
}

static void ft_extend_16_words(int i)
{
	int j;

	g_ssl->t = malloc(512);
	ft_bzero(g_ssl->t, 512);
	ft_memcpy(g_ssl->t, &g_ssl->bufer_32[i * 16], 32 * 16);
	j = 16;
	while (j < 64)
	{
		g_ssl->s0 = (rightrotate(g_ssl->t[j - 15], 7) ^ rightrotate(g_ssl->t[j - 15], 18) ^ (g_ssl->t[j - 15] >> 3));
		g_ssl->s1 = (rightrotate(g_ssl->t[j - 2], 17) ^ rightrotate(g_ssl->t[j - 2], 19) ^ (g_ssl->t[j - 2] >> 10));
		g_ssl->t[j] = g_ssl->t[j - 16] + g_ssl->s0 + g_ssl->t[j - 7] + g_ssl->s1;
		j++;
	}
	g_ssl->A = g_ssl->h0;
	g_ssl->B = g_ssl->h1;
	g_ssl->C = g_ssl->h2;
	g_ssl->D = g_ssl->h3;
	g_ssl->E = g_ssl->h4;
	g_ssl->F = g_ssl->h5;
	g_ssl->G = g_ssl->h6;
	g_ssl->H = g_ssl->h7;

}

static void ft_main_loop(int j)
{
	g_ssl->s1 = (rightrotate(g_ssl->E, 6) ^ rightrotate(g_ssl->E, 11) ^ rightrotate(g_ssl->E, 25));
	g_ssl->ch = (g_ssl->E & g_ssl->F) ^ (~g_ssl->E & g_ssl->G);
	g_ssl->temp1 = g_ssl->H + g_ssl->s1 + g_ssl->ch + g_K[j] + g_ssl->t[j];
	g_ssl->s0 = (rightrotate(g_ssl->A, 2) ^ rightrotate(g_ssl->A, 13) ^ rightrotate(g_ssl->A, 22));
	g_ssl->temp2 = ((g_ssl->A & g_ssl->B) ^ (g_ssl->A & g_ssl->C) ^ (g_ssl->B & g_ssl->C)) + g_ssl->s0;

	g_ssl->H = g_ssl->G;
	g_ssl->G = g_ssl->F;
	g_ssl->F = g_ssl->E;
	g_ssl->E = g_ssl->D + g_ssl->temp1;
	g_ssl->D = g_ssl->C;
	g_ssl->C = g_ssl->B;
	g_ssl->B = g_ssl->A;
	g_ssl->A = g_ssl->temp1 + g_ssl->temp2;
}

void ft_sha_256(char *slovo, int len)
{
	int	i;
//	int	len_block;
	int j;

//	len_block = 1 + g_ssl->len + 64 / 512;
	i = 0;
	ft_create_stream_date(slovo, ft_strlen(slovo));
	while (i < g_ssl->col_block)
	{
		ft_extend_16_words(i);
		j = 0;
		while (j < 64)
			ft_main_loop(j++);
		g_ssl->h0 += g_ssl->A;
		g_ssl->h1 += g_ssl->B;
		g_ssl->h2 += g_ssl->C;
		g_ssl->h3 += g_ssl->D;
		g_ssl->h4 += g_ssl->E;
		g_ssl->h5 += g_ssl->F;
		g_ssl->h6 += g_ssl->G;
		g_ssl->h7 += g_ssl->H;
		free(g_ssl->t);
		i++;
	}
}