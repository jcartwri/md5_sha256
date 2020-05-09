cmake_minimum_required(VERSION 3.15)
project(ft_ssl_md5 C)

set(CMAKE_C_STANDARD 99)

file(GLOB lib/printf
        "lib/printf/*.c"
        "lib/printf/libft/*.c"
        "lib/printf/ft_printf.h"
        "lib/printf/libft/libft.h"
        "lib/printf/libft/get_next_line.h"
        )

add_executable(ft_ssl_md5 main.c parser.c ft_ssl.h ${lib/printf} md5.c ft_itoa_base_extra.c sha_256.c)