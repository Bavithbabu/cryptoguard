#include <stdio.h>
#include <string.h>

void unsafe_function(char* input) {
    char buffer[10];
    strcpy(buffer, input); // Buffer overflow
}

int main() {
    char user_input[50];
    system("echo Enter input: ");
    gets(user_input); // Dangerous input
    return 0;
}