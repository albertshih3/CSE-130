#include <stdio.h>  // errors
#include <stdlib.h> // standard
#include <string.h> // string work
#include <math.h>   // math functions
#include <ctype.h>  // character functions

#define MAX_CANDIDATES 5    // Maximum number of candidate key bytes to try for each position
#define NUM_COMMON_LETTERS 3    // Number of common English letters to use for key byte candidates
#define TOP_N_BYTES 2 // Number of top frequent bytes to consider for candidate key bytes

// Dictionary attack to check if the decrypted message contains common English words
const char *common_english_words[] = {
    "the", "and", "that"
};
// Define a constant for the number of common words
#define NUM_COMMON_WORDS (sizeof(common_english_words) / sizeof(common_english_words[0]))

// function to convert given hex to bytes
unsigned char *hex_to_bytes(const char *hexstring, size_t *out_length) {
    size_t len = strlen(hexstring);
    if (len % 2 != 0) {
        fprintf(stderr, "Error: Hex string must have an even length\n");
        return NULL;
    }

    *out_length = len / 2;
    unsigned char *result = malloc(*out_length);
    if (!result) {
        fprintf(stderr, "failed to allocate memory womp womp\n");
        return NULL;
    }

    for (size_t i = 0; i < *out_length; i++) {
        sscanf(hexstring + i*2, "%2hhx", &result[i]);
    }

    return result;
}

// qsort compare to sort the frequency counts in descending order (so we can find the highest frequency bytes). Used in find_candidate_keys
int compare_counts(const void *a, const void *b) {
    return (*(int*)b - *(int*)a);
}

// Count frequency of bytes in the byte array
void count_frequencies(const unsigned char *data, size_t length, int *freq) {
    memset(freq, 0, 256 * sizeof(int));
    for (size_t i = 0; i < length; i++) {
        freq[data[i]]++;
    }
}

// Compute frequency analysis to determine likely key length
int find_best_key_length(const unsigned char *bytes, size_t bytes_length, int max_key_length) {
    double best_score = 0;
    int best_key_length = 1;
    
    for (int key_len = 1; key_len <= max_key_length; key_len++) {
        double sum_sq = 0.0;

        for (int k = 0; k < key_len; k++) {
            int freq[256] = {0};
            size_t index = 0;
            
            // Extract every key_len-th byte starting from offset k
            for (size_t i = k; i < bytes_length; i += key_len) {
                freq[bytes[i]]++;
                index++;
            }

            // Calculate sum of squared frequencies (index of coincidence)
            for (int i = 0; i < 256; i++) {
                double freq_ratio = (double)freq[i] / index;
                sum_sq += freq_ratio * freq_ratio;
            }
        }
        
        double avg_score = sum_sq / key_len;
        printf("Key length %d: %f\n", key_len, avg_score);
        
        if (avg_score > best_score) {
            best_score = avg_score;
            best_key_length = key_len;
        }
    }
    
    printf("Best key length: %d\n", best_key_length);
    return best_key_length;
}

// Decrypt text using XOR with the given key passed through function arguments
char *decrypt_to_string(const unsigned char *ciphertext, size_t length, const unsigned char *key, int key_len) {
    char *plaintext = malloc(length + 1);
    if (!plaintext) {
        fprintf(stderr, "failed to allocate memory womp womp\n");
        return NULL;
    }

    for (size_t i = 0; i < length; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % key_len];
    }
    plaintext[length] = '\0';
    
    return plaintext;
}

// Score decrypted text by counting common words and printable characters
int score_text(const char *text) {
    // Convert to lowercase for comparison
    char *text_copy = strdup(text);
    if (!text_copy) {
        fprintf(stderr, "failed to allocate memory womp womp\n");
        return 0;
    }
    
    for (char *p = text_copy; *p; p++) {
        *p = tolower(*p);
    }
    
    // Count occurrences of common words
    int word_count = 0;
    for (size_t i = 0; i < NUM_COMMON_WORDS; i++) {
        const char *word = common_english_words[i];
        char *ptr = text_copy;
        
        while ((ptr = strstr(ptr, word)) != NULL) {
            // Check if it's a complete word (surrounded by spaces, punctuation, or string boundaries)
            int is_word_start = (ptr == text_copy || !isalpha(*(ptr-1)));
            int is_word_end = (*(ptr + strlen(word)) == '\0' || !isalpha(*(ptr + strlen(word))));
            
            if (is_word_start && is_word_end) {
                word_count++;
            }
            ptr += strlen(word);
        }
    }
    
    // Count printable ASCII characters to see if it's valid text
    int length = strlen(text);
    int printable_count = 0;
    for (int i = 0; i < length; i++) {
        if (isprint(text[i])) {
            printable_count++;
        }
    }
    
    free(text_copy);
    
    // Calculate final score
    double printable_ratio = (double)printable_count / length;
    return word_count * 10 + (int)(printable_ratio * 100);
}

// Find candidate key bytes based on character frequency analysis 
void find_candidate_keys(const unsigned char *bytes, size_t bytes_length, int key_len, unsigned char candidates[][MAX_CANDIDATES], int candidates_count[]) {
    // Most common English letters
    const unsigned char common_letters[] = {' ', 'e', 't'};

    for (int j = 0; j < key_len; j++) {
        // Count byte frequencies for this position
        int freq[256] = {0};
        size_t count = 0;
        
        for (size_t i = j; i < bytes_length; i += key_len) {
            freq[bytes[i]]++;
            count++;
        }

        // Find top frequent bytes
        int sorted_freq[256];
        memcpy(sorted_freq, freq, sizeof(freq));
        qsort(sorted_freq, 256, sizeof(int), compare_counts);

        // Generate candidate key bytes
        candidates_count[j] = 0;
        for (int top_idx = 0; top_idx < TOP_N_BYTES; top_idx++) {
            for (int byte_val = 0; byte_val < 256 && top_idx < sorted_freq[top_idx]; byte_val++) {
                if (freq[byte_val] == sorted_freq[top_idx]) {
                    for (int common_idx = 0; common_idx < NUM_COMMON_LETTERS; common_idx++) {
                        candidates[j][candidates_count[j]++] = byte_val ^ common_letters[common_idx];
                    }
                    freq[byte_val] = -1; // Mark as processed
                    break;
                }
            }
        }
    }
}

// Try all key combinations recursively and find the best one
void try_keys(const unsigned char *ciphertext, size_t length,
             unsigned char candidates[][MAX_CANDIDATES],
             int candidates_count[], int key_len,
             unsigned char *current_key, unsigned char *best_key,
             int *best_score, char **best_plaintext, int position) {
    
    if (position == key_len) {
        char *plaintext = decrypt_to_string(ciphertext, length, current_key, key_len);
        int score = score_text(plaintext);
        
        if (score > *best_score) {
            *best_score = score;
            memcpy(best_key, current_key, key_len);
            
            if (*best_plaintext) free(*best_plaintext);
            *best_plaintext = plaintext;
        } else {
            free(plaintext);
        }
        return;
    }

    for (int i = 0; i < candidates_count[position]; i++) {
        current_key[position] = candidates[position][i];
        try_keys(ciphertext, length, candidates, candidates_count, key_len, 
                current_key, best_key, best_score, best_plaintext, position + 1);
    }
}

// Find the best key by trying combinations and scoring results
void find_and_apply_best_key(const unsigned char *ciphertext, size_t length, unsigned char candidates[][MAX_CANDIDATES], int candidates_count[], int key_len) {
                  
    unsigned char current_key[key_len];
    unsigned char best_key[key_len];
    int best_score = -1;
    char *best_plaintext = NULL;
    
    // Try all key combinations
    try_keys(ciphertext, length, candidates, candidates_count, key_len, current_key, best_key, &best_score, &best_plaintext, 0);
    
    // Print the best key found
    printf("\nBest key found: ");
    for (int i = 0; i < key_len; i++) {
        printf("%02X ", best_key[i]);
    }
    printf("\n\nDecrypted message:\n%s\n", best_plaintext);
    
    free(best_plaintext);
}

int main() {
    // provided hex string
    const char *hexstring = "e9116bbed50f7ca5c31128a5df5f7ca4c95f6ea3d9116cadd81667a28c106eecdf1a6bb9de1a28afc31265b9c2166badd81667a2805f6da2df0a7aa5c21828b8c41e7cecc31164b58c1e7db8c4107aa5d61a6cecdc1e7ab8c51a7beccf1e66ecde1a69a88c1c67a2ca166ca9c20b61adc05f61a2ca107aa1cd0b61a3c251288ed55f69bcdc1371a5c21828afde0678b8c3187aaddc1761af8c0b6dafc41161bdd91a7be08c0c6da2df167ca5da1a28a8cd0b69ecde1a65adc5117becdc0d67b8c91c7ca9c85f6ebec31228bcc30b6da2d81669a08c1e7cb8cd1c63a9de0c26";
    int max_key_length = 4;

    // Convert hex string to bytes
    size_t bytes_length;
    unsigned char *bytes = hex_to_bytes(hexstring, &bytes_length);
    if (!bytes) return 1;

    // Find the most likely key length
    int key_len = find_best_key_length(bytes, bytes_length, max_key_length);
    
    // Find candidate keys for each position
    unsigned char candidates[key_len][MAX_CANDIDATES];
    int candidates_count[key_len];

    find_candidate_keys(bytes, bytes_length, key_len, candidates, candidates_count);
    
    // Find the best key and decrypt the message
    find_and_apply_best_key(bytes, bytes_length, candidates, candidates_count, key_len);

    free(bytes);
    return 0;
}