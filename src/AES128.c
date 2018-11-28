#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AES128.h"

#define KEY_SIZE 16
#define ROUNDKEY_SIZE 176
#define STATE_SIZE 16

// 기약다항식 (m(x))
BYTE irrPolynomial = 0x1b;

BYTE doubleElement(BYTE currentValue) {
    // 비트 올림이 일어나는 경우
    if ((currentValue & 0x80) == 0x80) {
        currentValue <<= 1;
        currentValue ^= irrPolynomial;
    // 아닐 경우
    } else {
        currentValue <<= 1;
    }

    return currentValue;
}

BYTE multipleElement(BYTE repeat, BYTE stateValue) {
    BYTE temp = 0x00;
    BYTE original = stateValue;
    BYTE result = stateValue;
    BYTE twoCube = repeat / 0x08;
    temp = repeat % 0x08;
    BYTE twoSquare = temp / 0x04;
    temp = temp % 0x04;
    BYTE twoQuotient = temp / 0x02;
    temp = temp % 0x02;
    BYTE remainder = temp;

    if (twoCube != 0x00) {
        result = doubleElement(doubleElement(doubleElement(original)));
    }
    if (twoSquare != 0x00) {
        if (twoCube != 0x00) {
            result ^= doubleElement(doubleElement(original));
        } else {
            result = doubleElement(doubleElement(original));
        }
    }
    if (twoQuotient != 0x00) {
        if (twoCube != 0x00 || twoSquare != 0x00) {
            result ^= doubleElement(original);
        } else {
            result = doubleElement(original);
        }
    }
    // 만약 나머지가 존재할 경우 -> +1 (==XOR (self))
    if (repeat != 0x01) {
        if (remainder == 0x01) {
            result ^= stateValue;
        }
    }
    return result;
}

BYTE* rotWord(BYTE *colArr) {
    int size = sizeof(colArr);
    BYTE tempArr[size];

    tempArr[size - 1] = colArr[0];
    for (int i = 1; i < size; i++) {
        tempArr[i - 1] = colArr[i];
    }
    for (int i = 0; i < size; i++) {
        colArr[i] = tempArr[i];
    }
}

/*  <키스케줄링 함수>
 *   
 *  key         키스케줄링을 수행할 16바이트 키
 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
 */
void expandKey(BYTE *key, BYTE *roundKey) {
    int keyRowSize = KEY_SIZE / 4;
    int roundKeyRowSize = ROUNDKEY_SIZE / 4;
    int rConRowSize = sizeof(r_con) / 4;
    int rConCount = 0;
    BYTE tempArr[4];
    BYTE tempArr2[4];

    for (int i = 0; i < keyRowSize; i++) {
        for (int j = 0; j < 4; j++) {
            roundKey[(j * (ROUNDKEY_SIZE / 4)) + i] = key[(j * keyRowSize) + i];
        }
    }
    
    for (int i = keyRowSize; i < (ROUNDKEY_SIZE / 4); i++) {
        for (int j = 0; j < 4; j++) {
            tempArr[j] = roundKey[(j * (ROUNDKEY_SIZE / 4)) + (i - 1)];
        }
        if (i % 4 == 0) {
            rotWord(tempArr);
            subBytes(tempArr, ENC);
            memcpy(tempArr2, tempArr, 4);
            for (int k = 0; k < 4; k++) {
                tempArr2[k] ^= r_con[((sizeof(r_con) / 4) * k) + rConCount];
            }
            memcpy(tempArr, tempArr2, 4);
            rConCount ++;
        }
        for (int j = 0; j < 4; j++) {
            roundKey[(j * (ROUNDKEY_SIZE / 4)) + i] = roundKey[(j * (ROUNDKEY_SIZE / 4)) + (i - 4)] ^ tempArr[j];
        }
    }
}


/*  <SubBytes 함수>
 *   
 *  state   SubBytes 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    SubBytes 수행 모드
 */
BYTE* subBytes(BYTE *state, int mode) {
    BYTE element, front, back;

    switch (mode) {

        case ENC:
            for (int i = 0; i < STATE_SIZE; i++) {
                element = state[i];
                front = element >> 4;
                back = element & 0x0f;

                state[i] = sbox[front][back];
            }
            
            break;

        case DEC:
            for (int i = 0; i < STATE_SIZE; i++) {
                element = state[i];
                front = element >> 4;
                back = element & 0x0f;

                state[i] = inverse_sbox[front][back];
            }
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <ShiftRows 함수>
 *   
 *  state   ShiftRows 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    ShiftRows 수행 모드
 */
BYTE* shiftRows(BYTE *state, int mode) {
    int matrixRowSize = STATE_SIZE / 4;
    BYTE firstRow[matrixRowSize];
    BYTE secondRow[matrixRowSize];
    BYTE thirdRow[matrixRowSize];

    switch (mode) {

        case ENC:
            // shift 후 temp 에 insert
            for (int i = 0; i < STATE_SIZE; i++) {
                if (i / matrixRowSize == 0) {
                    continue;
                } else if (i / matrixRowSize == 1) {
                    if (i % matrixRowSize == 0) {
                        firstRow[matrixRowSize - 1] = state[i];
                    } else {
                        firstRow[i % matrixRowSize - 1] = state[i];
                    }
                } else if (i / matrixRowSize == 2) {
                    if (i % matrixRowSize == 0) {
                        secondRow[matrixRowSize - 2] = state[i];
                    } else if (i % matrixRowSize == 1) {
                        secondRow[matrixRowSize - 1] = state[i];
                    } else {
                        secondRow[i % matrixRowSize - 2] = state[i];
                    }
                } else if (i / matrixRowSize == 3) {
                    if (i % matrixRowSize == 0) {
                        thirdRow[matrixRowSize - 3] = state[i];
                    } else if (i % matrixRowSize == 1) {
                        thirdRow[matrixRowSize - 2] = state[i];
                    } else if (i % matrixRowSize == 2) {
                        thirdRow[matrixRowSize - 1] = state[i];
                    } else {
                        thirdRow[i % matrixRowSize - 3] = state[i];
                    }
                }
            }
            // temp 의 값들을 순서대로 state 에 replace
            for (int i = 0; i < STATE_SIZE; i++) {
                if (i / matrixRowSize == 0) {
                    continue;
                } else if (i / matrixRowSize == 1) {
                    state[i] = firstRow[i % matrixRowSize];
                } else if (i / matrixRowSize == 2) {
                    state[i] = secondRow[i % matrixRowSize];
                } else if (i / matrixRowSize == 3) {
                    state[i] = thirdRow[i % matrixRowSize];
                }
            }
            
            break;

        case DEC:
            // shift 후 temp 에 insert
            for (int i = 0; i < STATE_SIZE; i++) {
                if (i / matrixRowSize == 0) {
                    continue;
                } else if (i / matrixRowSize == 1) {
                    if (i % matrixRowSize == 3) {
                        firstRow[matrixRowSize - 4] = state[i];
                    } else {
                        firstRow[i % matrixRowSize + 1] = state[i];
                    }
                } else if (i / matrixRowSize == 2) {
                    if (i % matrixRowSize == 3) {
                        secondRow[matrixRowSize - 3] = state[i];
                    } else if (i % matrixRowSize == 2) {
                        secondRow[matrixRowSize - 4] = state[i];
                    } else {
                        secondRow[i % matrixRowSize + 2] = state[i];
                    }
                } else if (i / matrixRowSize == 3) {
                    if (i % matrixRowSize == 3) {
                        thirdRow[matrixRowSize - 2] = state[i];
                    } else if (i % matrixRowSize == 2) {
                        thirdRow[matrixRowSize - 3] = state[i];
                    } else if (i % matrixRowSize == 1) {
                        thirdRow[matrixRowSize - 4] = state[i];
                    } else {
                        thirdRow[i % matrixRowSize + 3] = state[i];
                    }
                }
            }
            // temp 의 값들을 순서대로 state 에 replace
            for (int i = 0; i < STATE_SIZE; i++) {
                if (i / matrixRowSize == 0) {
                    continue;
                } else if (i / matrixRowSize == 1) {
                    state[i] = firstRow[i % matrixRowSize];
                } else if (i / matrixRowSize == 2) {
                    state[i] = secondRow[i % matrixRowSize];
                } else if (i / matrixRowSize == 3) {
                    state[i] = thirdRow[i % matrixRowSize];
                }
            }
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <MixColumns 함수>
 *   
 *  state   MixColumns을 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    MixColumns의 수행 모드
 */
BYTE* mixColumns(BYTE *state, int mode) {
    int stateRowSize = STATE_SIZE / 4;
    int mixColumArraySize = sizeof(mixColumn_array) / 4;
    BYTE tempState[STATE_SIZE];
    BYTE currentValue = 0x00;

    memcpy(tempState, state, STATE_SIZE);

    switch (mode) {

        case ENC:
            for (int k = 0; k < mixColumArraySize; k++) {
                for (int i = 0; i < stateRowSize; i++) {
                    currentValue = multipleElement(mixColumn_array[k * mixColumArraySize], tempState[i]);

                    for (int j = 1; j < mixColumArraySize; j++) {
                        currentValue ^= multipleElement(mixColumn_array[(k * mixColumArraySize) + j], tempState[(stateRowSize * j) + i]);
                    }
                    state[(k * stateRowSize) + i] = currentValue;
                }
            }
            
            break;

        case DEC:
            for (int k = 0; k < mixColumArraySize; k++) {
                for (int i = 0; i < stateRowSize; i++) {
                    currentValue = multipleElement(inverse_mixColumn_array[k * mixColumArraySize], tempState[i]);

                    for (int j = 1; j < mixColumArraySize; j++) {
                        currentValue ^= multipleElement(inverse_mixColumn_array[(k * mixColumArraySize) + j], tempState[(stateRowSize * j) + i]);
                    }
                    state[(k * stateRowSize) + i] = currentValue;
                }
            }
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <AddRoundKey 함수>
 *   
 *  state   AddRoundKey를 수행할 16바이트 state. 수행 결과는 해당 배열에 반영
 *  rKey    AddRoundKey를 수행할 16바이트 라운드키
 */
BYTE* addRoundKey(BYTE *state, BYTE *rKey){
    BYTE rKeyImpl[ROUNDKEY_SIZE];
    memcpy(rKeyImpl, rKey, ROUNDKEY_SIZE);

    for (int i = 0; i < (STATE_SIZE / 4); i++) {
        for (int j = 0; j < 4; j++) {
            state[((STATE_SIZE / 4) * j) + i] ^= rKeyImpl[((STATE_SIZE / 4) * j) + i];
        }
    }

    return state;
}


/*  <128비트 AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  input   평문 바이트 배열
 *  result  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 *
 *  [DEC 모드]
 *  input   암호문 바이트 배열
 *  result  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 */
void AES128(BYTE *input, BYTE *result, BYTE *key, int mode) {

    if (mode == ENC) {
        BYTE stateT[STATE_SIZE];
        BYTE keyT[KEY_SIZE];
        BYTE roundKey[ROUNDKEY_SIZE];
        BYTE tempRound[4];
        int keyRowSize = KEY_SIZE / 4;
        int roundKeyRowSize = ROUNDKEY_SIZE / 4;
        int count = 0;
        int repeatNumber = 0;
        if (KEY_SIZE == 16) {
            repeatNumber = 10;
        } else if (KEY_SIZE == 24) {
            repeatNumber = 12;
        } else if (KEY_SIZE == 32) {
            repeatNumber = 14;
        }

        for (int i = 0; i < STATE_SIZE / 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateT[(j * (STATE_SIZE / 4)) + i] = input[count];
                count ++;
            }
        }
        memcpy(input, stateT, STATE_SIZE);
        count = 0;
        for (int i = 0; i < keyRowSize; i++) {
            for (int j = 0; j < 4; j++) {
                keyT[(j * keyRowSize) + i] = key[count];
                count ++;
            }
        }
        expandKey(keyT, roundKey);
        count = 0;

        addRoundKey(input, keyT);
        for (int i = 0; i < repeatNumber; i++) {
            for (int j = 0; j < STATE_SIZE; j++) {
                if (j / 4 == 0) {
                    tempRound[j] = roundKey[((i + 1) * 4) + (j % 4)];
                } else if (j / 4 == 1) {
                    tempRound[j] = roundKey[roundKeyRowSize + ((i + 1) * 4) + (j % 4)];
                } else if (j / 4 == 2) {
                    tempRound[j] = roundKey[roundKeyRowSize * 2 + ((i + 1) * 4) + (j % 4)];
                } else if (j / 4 == 3) {
                    tempRound[j] = roundKey[roundKeyRowSize * 3 + ((i + 1) * 4) + (j % 4)];
                }
            }
            subBytes(input, ENC);
            shiftRows(input, ENC);
            if (i < (repeatNumber - 1)) {
                mixColumns(input, ENC);
            }
            addRoundKey(input, tempRound);
        }
        for (int i = 0; i < STATE_SIZE / 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateT[(j * (STATE_SIZE / 4)) + i] = input[count];
                count ++;
            }
        }
        count = 0;
        memcpy(result, stateT, STATE_SIZE);

    } else if (mode == DEC) {
        BYTE keyT[KEY_SIZE];
        BYTE stateT[STATE_SIZE];
        BYTE roundKey[ROUNDKEY_SIZE];
        BYTE tempRound[4];
        int keyRowSize = KEY_SIZE / 4;
        int roundKeyRowSize = ROUNDKEY_SIZE / 4;
        int count = 0;
        int repeatNumber = 0;
        if (KEY_SIZE == 16) {
            repeatNumber = 10;
        } else if (KEY_SIZE == 24) {
            repeatNumber = 12;
        } else if (KEY_SIZE == 32) {
            repeatNumber = 14;
        }

        for (int i = 0; i < STATE_SIZE / 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateT[(j * (STATE_SIZE / 4)) + i] = input[count];
                count ++;
            }
        }
        memcpy(input, stateT, STATE_SIZE);
        count = 0;

        for (int i = 0; i < keyRowSize; i++) {
            for (int j = 0; j < 4; j++) {
                keyT[(j * keyRowSize) + i] = key[count];
                count ++;
            }
        }
        count = 0;
        expandKey(keyT, roundKey);

        for (int i = (repeatNumber - 1); i >= 0; i--) {
            for (int j = 0; j < STATE_SIZE; j++) {
                if (j / 4 == 0) {
                    tempRound[j] = roundKey[((i + 1) * 4) + (j % 4)];
                } else if (j / 4 == 1) {
                    tempRound[j] = roundKey[roundKeyRowSize + ((i + 1) * 4) + (j % 4)];
                } else if (j / 4 == 2) {
                    tempRound[j] = roundKey[roundKeyRowSize * 2 + ((i + 1) * 4) + (j % 4)];
                } else if (j / 4 == 3) {
                    tempRound[j] = roundKey[roundKeyRowSize * 3 + ((i + 1) * 4) + (j % 4)];
                }
            }
            addRoundKey(input, tempRound);
            if (i < (repeatNumber - 1)) {
                mixColumns(input, DEC);
            }
            shiftRows(input, DEC);
            subBytes(input, DEC);
        }
        addRoundKey(input, keyT);
        for (int i = 0; i < STATE_SIZE / 4; i++) {
            for (int j = 0; j < 4; j++) {
                stateT[(j * (STATE_SIZE / 4)) + i] = input[count];
                count ++;
            }
        }
        count = 0;
        memcpy(result, stateT, STATE_SIZE);

    } else {
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}
