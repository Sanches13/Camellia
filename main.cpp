#include <iostream>
#include <cstring>
#include "encryption.cpp"

uint32_t get_file_size(FILE *fp) {
    fseek(fp, 0, SEEK_END);
    uint32_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return file_size;
}

uint32_t key_verification(FILE* key_file, uint8_t *my_key) {
    if(get_file_size(key_file) != KEY_SIZE_IN_BYTES){
        std::cout << "Incorrect length of key!" << std::endl;
        return -1;
    }

    for(int i = 0; i < KEY_SIZE_IN_BYTES; i++)
        fscanf(key_file, "%c", &my_key[i]);

    return 0;
}

int main(int argc, char* argv[]) {
    if(argc != 5){
        std::cout << "Please, use format: " << argv[0] << " <key> <input_file> <output_file> <mode>";
        return -1;
    }

    if(strcmp(argv[4], ENCRYPTION_MODE) != 0 && strcmp(argv[4], DECRYPTION_MODE) != 0 || (strlen(argv[4]) != 2)) {
        std::cout << "Error value of mode!" << std::endl;
        return -1;
    }

    uint8_t key[KEY_SIZE_IN_BYTES] = {0};
    FILE *key_file;
    if((key_file = fopen(argv[1], "rb")) == nullptr){
        std::cout << "Error when opening key file!" << std::endl;
        return -1;
    }
    if((key_verification(key_file, key)) != 0) {
        fclose(key_file);
        return -1;
    }
    fclose(key_file);
    std::cout << "Key file opened" << std::endl;

    FILE *input, *output;
    if((input = fopen(argv[2], "rb")) == nullptr){
        std::cout << "Error when opening input file" << std::endl;
        return -1;
    }
    std::cout << "Input file opened" << std::endl;

    uint32_t file_size = get_file_size(input);
    if(file_size == 0){
        std::cout << "Your input file is empty!" << std::endl;
        fclose(input);
        return -1;
    }

    if((output = fopen(argv[3], "wb")) == nullptr){
        std::cout << "Error when creating output file" << std::endl;
        fclose(input);
        return -1;
    }
    std::cout << "Output file created" << std::endl;

    std::cout << "Start encrypting/decrypting the file..." << std::endl;
    if(strcmp(argv[4], ENCRYPTION_MODE) == 0)
        fprintf(output, "%c", (BLOCK_SIZE_IN_BYTES - (file_size % BLOCK_SIZE_IN_BYTES)) % BLOCK_SIZE_IN_BYTES);
    else {
        uint8_t elem;
        fscanf(input, "%c", &elem);
        file_size = file_size - 1 - elem;
    }

    uint32_t num_of_blocks;
    if(file_size % BLOCK_SIZE_IN_BYTES == 0)
        num_of_blocks = file_size / BLOCK_SIZE_IN_BYTES;
    else
        num_of_blocks = (file_size / BLOCK_SIZE_IN_BYTES) + 1;

    subkeys ptr;
    keygen(&ptr, key, argv[4]);
    uint8_t plaintext[16], ciphertext[16];

    for(int k = 0; k < num_of_blocks; k++){
        memset(plaintext, 0, BLOCK_SIZE_IN_BYTES);
        memset(ciphertext, 0, BLOCK_SIZE_IN_BYTES);

        for(int i = 0; i < BLOCK_SIZE_IN_BYTES && (i < file_size || k == 0); i++)
            fscanf(input, "%c", &plaintext[i]);

        encryption(plaintext, ciphertext, &ptr);

        if(strcmp(argv[4], DECRYPTION_MODE) == 0)
            for(int i = 0; i < BLOCK_SIZE_IN_BYTES && (i + k * BLOCK_SIZE_IN_BYTES) < file_size; i++)
                fprintf(output, "%c", ciphertext[i]);
        else
            for(int i = 0; i < BLOCK_SIZE_IN_BYTES; i++)
                fprintf(output, "%c", ciphertext[i]);
    }

    std::cout << "Your file is encrypted/decrypted successfully!" << std::endl;
    fclose(input);
    fclose(output);
    return 0;
}
