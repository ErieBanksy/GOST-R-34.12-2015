#include <iostream>

#include "gost12_15.h"

using std::string;

void LTransformationExample();
void STransformationExample();
void XTransformationExample();

void encryptDecryptExample(vector<vector<uint8_t>> roundKeys);
void gammaCryptionExample(vector<vector<uint8_t>> roundKeys);

void imitoGenerationExample(vector<vector<uint8_t>> roundKeys);

int main() {
    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> generalKey = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    g.initRoundConsts();
    vector<vector<uint8_t>> roundKeys = g.generatingRoundKeys(generalKey);

    LTransformationExample();
    STransformationExample();
    XTransformationExample();

    encryptDecryptExample(roundKeys);
    gammaCryptionExample(roundKeys);

    imitoGenerationExample(roundKeys);

    system("pause");
}


/**
* \brief Функция демонстрирущая пример работы линейного преобразования.
*/
void LTransformationExample() {
    cout << "------------------------" << endl;
    cout << "Testing L transformation" << endl;
    cout << "------------------------" << endl;

    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> data = {
        0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    cout << "Data for L transformation: " << endl;
    for (size_t i = 0; i < data.size(); i++) {
        cout << "0x" << std::hex << (int)data[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataL = g.LTransformation(g.inverseData(data));
    dataL = g.inverseData(dataL);

    cout << "Data after L: " << endl;
    for (size_t i = 0; i < 16; i++) {
        cout << "0x" << std::hex << (int)dataL[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataLL = g.LTransformation(g.inverseData(dataL));
    dataLL = g.inverseData(dataLL);

    cout << "Data after LL: " << endl;
    for (size_t i = 0; i < 16; i++) {
        cout << "0x" << std::hex << (int)dataLL[i] << " ";
    }
    cout << endl;
    cout << "------------------------" << endl;
}


/**
* \brief Функция демонстрирущая пример работы нелинейного преобразования.
*/
void STransformationExample() {
    cout << "Testing S transformation" << endl;
    cout << "------------------------" << endl;

    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> data = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00
    };

    cout << "Data for S transformation: " << endl;
    for (size_t i = 0; i < data.size(); i++) {
        cout << "0x" << std::hex << (int)data[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataS = g.STransformation(g.inverseData(data));
    dataS = g.inverseData(dataS);

    cout << "Data after S: " << endl;
    for (size_t i = 0; i < 16; i++) {
        cout << "0x" << std::hex << (int)dataS[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataSS = g.STransformation(g.inverseData(dataS));
    dataSS = g.inverseData(dataSS);

    cout << "Data after SS: " << endl;
    for (size_t i = 0; i < 16; i++) {
        cout << "0x" << std::hex << (int)dataSS[i] << " ";
    }
    cout << endl;
    cout << "------------------------" << endl;
}


/**
* \brief Функция демонстрирущая пример работы перестановки.
*/
void XTransformationExample() {
    cout << "Testing X transformation" << endl;
    cout << "------------------------" << endl;

    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> data = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };

    vector<uint8_t> key1 = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };

    cout << "Data for X transformation: " << endl;
    for (size_t i = 0; i < data.size(); i++) {
        cout << "0x" << std::hex << (int)data[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataXkey = g.XTransformation(data, key1);

    cout << "Data after X: " << endl;
    for (size_t i = 0; i < 16; i++) {
        cout << "0x" << std::hex << (int)dataXkey[i] << " ";
    }
    cout << endl;
    cout << "-----------------------------" << endl;
}


/**
* \brief Функция демонстрирущая пример работы LSX преобразования.
*
* \param [in] roundKeys - матрица раундовых ключей.
*/
void encryptDecryptExample(vector<vector<uint8_t>> roundKeys) {
    cout << "Testing encryption/decryption" << endl;
    cout << "-----------------------------" << endl;

    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> data = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };

    cout << "Data: " << endl;
    for (size_t i = 0; i < data.size(); i++) {
        cout << "0x" << std::hex << (int)data[i] << " ";
    }
    cout << endl;

    vector<uint8_t> encData(16, 0);
    encData = g.LSXEncryptData(data, roundKeys);

    cout << "Enc data: " << endl;
    for (size_t i = 0; i < encData.size(); i++) {
        cout << "0x" << std::hex << (int)encData[i] << " ";
    }
    cout << endl;

    vector<uint8_t> decData(16, 0);
    decData = g.LSXDecryptData(encData, roundKeys);

    cout << "Dec data: " << endl;
    for (size_t i = 0; i < decData.size(); i++) {
        cout << "0x" << std::hex << (int)decData[i] << " ";
    }
    cout << endl;
    cout << "----------------------" << endl;
}


/**
* \brief Функция демонстрирущая пример работы шифрования в режиме гаммирования.
*
* \param [in] roundKeys - матрица раундовых ключей.
*/
void gammaCryptionExample(vector<vector<uint8_t>> roundKeys) {
    cout << "Testing gamma cryption" << endl;
    cout << "----------------------" << endl;

    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> data = {
        0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0x43, 0xa1, 0x75, 0x00, 0x00, 0x00, 0x00, 0x1b
    };

    vector<uint8_t> sync = {
        0x64, 0xa5, 0x94, 0x78, 0xa1, 0x41, 0xf2, 0x5e
    };

    cout << "Data: " << endl;
    for (size_t i = 0; i < data.size(); i++) {
        cout << "0x" << std::hex << (int)data[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataEnc = g.gammaCryption(data, sync, roundKeys);
    cout << "Data: Encryption" << endl;
    for (size_t i = 0; i < dataEnc.size(); i++) {
        cout << "0x" << std::hex << (int)dataEnc[i] << " ";
    }
    cout << endl;
    cout << endl;

    vector<uint8_t> dataDec = g.gammaCryption(dataEnc, sync, roundKeys);
    cout << "Data: Encryption" << endl;
    for (size_t i = 0; i < dataDec[dataDec.size() - 1]; i++) {
        cout << "0x" << std::hex << (int)dataDec[i] << " ";
    }
    cout << endl;
    cout << "------------------------" << endl;
}


/**
* \brief Функция демонстрирущая пример генерации имитовставки.
*
* \param [in] roundKeys - матрица раундовых ключей.
*/
void imitoGenerationExample(vector<vector<uint8_t>> roundKeys) {
    cout << "Testing imito generation" << endl;
    cout << "------------------------" << endl;

    gost12_15 &g = gost12_15::getInstance();

    vector<uint8_t> data = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xee, 0xff, 0x0a, 0x00, 0x11
    };

    vector<uint8_t> imito(8, 0);
    imito = g.imitoGeneration(data, roundKeys);

    cout << "Imito: " << endl;
    for (size_t i = 0; i < imito.size(); i++) {
        cout << "0x" << std::hex << (int)imito[i] << " ";
    }
    cout << endl;

    vector<uint8_t> checkImito = {
        0x33, 0x6f, 0x4d, 0x29, 0x60, 0x59, 0xfb, 0xe3
    };

    cout << "Check imito: " << endl;
    for (size_t i = 0; i < imito.size(); i++) {
        cout << "0x" << std::hex << (int)imito[i] << " ";
    }
    cout << endl;
    cout << "------------------------" << endl;
}
