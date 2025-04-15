#include <stdio.h>
#include <string.h>

void safe_function(const char* input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);  // Ensure buffer is not overrun
    buffer[sizeof(buffer) - 1] = '\0';  // Null-terminate manually
}

int main() {
    char user_input[50];

    printf("Enter input: ");
    fgets(user_input, sizeof(user_input), stdin);  // Safe alternative to gets()
    
    // Remove the newline character if present
    user_input[strcspn(user_input, "\n")] = '\0'; 

    safe_function(user_input);
    
    return 0;
}
