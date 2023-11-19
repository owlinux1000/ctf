#include <stdio.h>
#include <stdlib.h>

void main() {
    unsigned long *p1 = malloc(0x90);
    free(p1);
    // UAFで解放済みチャンクを参照できた場合を想定
    printf("*p1: %lx\n", *p1);
    // GLIBC 2.32以降では、Safe Linkingの仕組みが導入されている
    // tcacheのnextとなる値を、自身のチャンクのアドレスとリンク先を使って算出する (PROTECT_PTRマクロ)
    // しかしながら、tcache binsに初めて繋がれるチャンクは、0とXORされるため、bitシフトだけ戻せばヒープのアドレスがリークされる
    // なおかつ、この算出には下位3 nibbleが利用されないため、bitシフトを戻すことでヒープベースをリークできることと等しくなる
    printf("heap base: %lx\n", *p1 << 12);
}