#ifndef FT_SSL_H
#define FT_SSL_H

#include "./lib/printf/ft_printf.h"
#include "./lib/printf/libft/libft.h"
#include "./lib/printf/libft/get_next_line.h"
#include <stdint.h>

# define F(X, Y, Z) ((X & Y) | (~X & Z))
# define G(X, Y, Z) ((X & Z) | (~Z & Y))
# define H(X, Y, Z) (X ^ Y ^ Z)
# define I(X, Y, Z) (Y ^ (~Z | X))
# define leftrotate(X, N) ((X << N) | (X >> (32 - N)))
# define rightrotate(X, N) ((X >> N) | (X << (32 - N)))


int		main(int argc, char **argv);
void	ft_parser(void);

typedef struct	s_ssl
{
	uint32_t		A;
	uint32_t		B;
	uint32_t		C;
	uint32_t		D;
	uint32_t		E;
	uint32_t		F;
	uint32_t		G;
	uint32_t		H;
	uint32_t		a0;
	uint32_t		b0;
	uint32_t		c0;
	uint32_t		d0;
	uint32_t		*t;
	uint32_t		h0;
	uint32_t		h1;
	uint32_t		h2;
	uint32_t		h3;
	uint32_t		h4;
	uint32_t		h5;
	uint32_t		h6;
	uint32_t		h7;
	uint32_t		s0;
	uint32_t		s1;
	uint32_t		ch;
	uint32_t		temp1;
	uint32_t		temp2;
	int 			len;
	char 			*str;
	char			*bufer;
	uint32_t 		*bufer_32;
	int 			col_block;
	uint32_t		new_t[512];
}				t_ssl;

t_ssl			*g_ssl;

void			ft_md5(char *slovo, int len);
char			*ft_itoa_base_extra(uint32_t n, int base);
void			ft_sha_256(char *slovo, int len);
uint32_t		revers_uint32(uint32_t n);

#endif