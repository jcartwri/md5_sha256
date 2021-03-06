#include <stdio.h>
#include "ft_ssl.h"
#include <math.h>

static void	ft_creat_ssl(void)
{
	t_ssl	*ssl;

	ssl = (t_ssl *)malloc(sizeof(t_ssl));
	ssl->str = NULL;
	g_ssl = ssl;
}

uint32_t	revers_uint32(uint32_t n)
{
	return ((n >> 24) | ((n & 0xff0000) >> 8) |
		((n & 0xff00) << 8) | (n << 24));
}

char	*ft_add_null(char *temp)
{
	int i;

	i = ft_strlen(temp);
	while (i < 8)
	{
		ft_putstr("0");
		i++;
	}
	return (temp);
}

static int ft_run_md5(char *str)
{
	ft_md5(str, ft_strlen(str));
	str = ft_itoa_base_extra(revers_uint32(g_ssl->a0), 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(revers_uint32(g_ssl->b0), 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(revers_uint32(g_ssl->c0), 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(revers_uint32(g_ssl->d0), 16);
	ft_add_null(str);
	ft_putstr(str);
	return (0);
}

static int ft_run_sha256(char *str)
{
	ft_sha_256(str, ft_strlen(str));
	str = ft_itoa_base_extra(g_ssl->h0, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h1, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h2, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h3, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h4, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h5, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h6, 16);
	ft_add_null(str);
	ft_putstr(str);
	str = ft_itoa_base_extra(g_ssl->h7, 16);
	ft_add_null(str);
	ft_putstr(str);
	return (0);
}

int main(int argc, char **argv)
{
	char *str;

	str = "HI";
	ft_creat_ssl();
//	ft_run_md5(str);
	ft_run_sha256(str);
//	u_int32_t mas1[10];
//	ft_bzero(mas1, 10);
//	char	mas2[10] = "0123";
//	u_int32_t *new_mas;
//	new_mas = ft_memcpy(mas1, mas2, 10);
	return 0;
}