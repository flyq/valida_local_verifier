/*
 * Copyright © [2024] Lita Inc. All Rights Reserved.
 *
 * This software and associated documentation files (the “Software”) are owned by Lita Inc. and are protected by copyright law and international treaties.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to use the Software for personal, non-commercial purposes only, subject to the following conditions:
 *
 * 1. The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 2. The Software may not be used for commercial purposes without the express written permission of Lita Inc.
 *
 * For inquiries regarding commercial use, please contact us at: ops@lita.foundation
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

// Example usage:
// morgan@aristotle:~/code/lita/issue/examples$ .llvm-valida/build/bin/clang -c -target delendum ./valida-c-examples/cat.c 
// morgan@aristotle:~/code/lita/issue/examples$ ./llvm-valida/build/bin/ld.lld --script=./llvm-valida/valida.ld ./cat.o 
// morgan@aristotle:~/code/lita/issue/examples$ ./valida/target/release/valida run ./a.out log
// 12345
// morgan@aristotle:~/code/lita/issue/examples$ cat log
// 12345

const unsigned EOF = 0xFFFFFFFF;

int main() {
    unsigned c = 0;
    while (1) {
        c = __builtin_delendum_read_advice();
        if (c == EOF) {
            break;
        } else {
            __builtin_delendum_write(c);
        }
    }
}
