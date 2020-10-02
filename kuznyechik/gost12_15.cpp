#include <cstring>

#include "gost12_15.h"


/**
* \brief ������� ��������� ����� � �������� ���� ��� ������������ ���������.
*
* ��������� ���������� ��� ����� ����� GF(2^8) ��� ������������ ��������� x^8 + x^7 + x^6 + x + 1.
* ���� ������� � ��������� � ������� � ����������� ����� 0x�3, ������� � ������������ ������ ��� �������.
*
* \param [in] polynom1 � ������ ��������� ��� ���������.
* \param [in] polynom2 � ������ ��������� ��� ���������.
* \return ���������� ��������� ��������� ���� �����������.
*/
uint8_t gost12_15::galoisMult(uint8_t polynom1, uint8_t polynom2) {
    uint8_t multRes = 0;
    uint8_t highBit;

    for (int i = 0; i < 8; i++) {
        if (polynom2 & 1) {
            multRes = multRes ^ polynom1;
        }

        highBit = polynom1 & 0x80; //��������� ������� ���
        polynom1 = static_cast<uint8_t>(polynom1 << 1);

        if (highBit) {
            polynom1 = polynom1 ^ this->generatingPolynom; // ����������� ������� ���������� �� polynom1
        }

        polynom2 = static_cast<uint8_t>(polynom2 >> 1);
    }

    return multRes;
}


/**
* \brief ������� ��������� �������� ������������������ �� ������������ l �������.
*
* ������ ���� �� ����� ���������� � ������� ������� galoisMult �� ���� �� ������������� �� ���� lCoefficients
* � ����������� �� ����������� ������ �����. ����� ������������ ����� ����� �� ������ 2 (xor).
* �������� xor �������� ��������� ��� ����� ����� GT(2^8) � ������������ ����������� x^8 + x^7 + x^6 + x + 1.
* ������� ������������ ��� ����������.
*
* \param [in] data � �������� ������� ������������������ ���� ������� 16.
* \return ���������� ������� 7-� �������, ������� ����������� � �������� ����.
*/
uint8_t gost12_15::lFunc(vector<uint8_t> data) {
    uint8_t la = 0;

    for (int i = 0; i < blockSize; i++) {
        la = la ^ galoisMult(data[i], lCoefficients[i]);
    }

    return la;
}


/**
* \brief ������� �������� � lFunc.
*
* � ������� ����� ������ ���� �� ����� ���������� � ������� ������� galoisMult �� ���� �� �������������
* �� ���� lCoefficients, �� ������� ���� ������������� �������.
* ������� ������������ � ��������� �������������.
*
* \param [in] data � ������������� ������� ������������������ ���� ������� 16.
* \return ���������� ������� 7-� �������, ������� ����������� � �������� ����.
*/
uint8_t gost12_15::inverselFunc(vector<uint8_t> data) {
    uint8_t la = 0;

    for (int i = blockSize - 2; i >= 0; i--) {
        la = la ^ galoisMult(data[i], lCoefficients[i + 1]);
    }
    la = la ^ galoisMult(data[blockSize - 1], lCoefficients[0]);

    return la;
}


/**
* \brief ������� ��������� ��������������.
*
* �������� ������������� L ����� ��������� ����� ���� ������� � ������� ��������� �������� ������ R:
* 1. ��� ������� ����� �� ����������� ���� ����� ������� ������������������ ����������� ������� lFunc(data).
* 2. ���������� �� ���������� ���� ��������� ������������ ������ � ������ ������, ����� ������������ ��� �����
*    ������� ������������������ data, ����� �������� (����������) .
* ����� �������, ���������� ������������ ����� ������ ������ � ������ �� ���� ����.
* ���� ����������� 16 ���, ������� ������������ ��� ������������ ������.
*
* \param [in] data � �������� ������� ������������������ ���� ������� 16.
* \return ���������� ������� ��������������� ������� ������������������ .
*/
vector<uint8_t> gost12_15::LTransformation(vector<uint8_t> data) {
    uint8_t la = 0;
    vector<uint8_t> rData = data;

    for (int i = 0; i < blockSize; i++) {
        la = lFunc(rData);
        for (int j = 0; j < blockSize - 1; j++) {
            rData[j] = rData[j + 1];
        }
        rData[blockSize - 1] = la;
    }

    return rData;
}


/**
* \brief ������� ��������� ��������� ��������������.
*
* 1. ��� ������� ����� �� ����������� ���� ����� ������� ������������������ ����������� ������� inverselFunc(data).
* 2. ���������� �� ���������� ���� ��������� ������������ ��������� � ������ ������, ����� ������������ ��� �����
*    ������� ������������������ data, ����� �������� (�������).
* ���� ����������� 16 ���, ������� ������������ ��� ������������� ������.
*
* \param [in] data � ������������� ������� ������������������ ���� ������� 16.
* \return ���������� �������������� ������� ������������������.
*/
vector<uint8_t> gost12_15::inverseLTransformation(vector<uint8_t> data) {
    uint8_t la = 0;
    vector<uint8_t> rData = data;

    for (int i = 0; i < blockSize; i++) {
        la = inverselFunc(rData);
        for (int j = blockSize - 1; j > 0; j--) {
            rData[j] = rData[j - 1];
        }
        rData[0] = la;
    }

    return rData;
}


/**
* \brief ������� ����������� ��������������.
*
* ���������� S �������������� � ��������� ����������� ����� ������.
* � ������� ����� ����������� ���������� �����������, ���������� �������� STable.
* ����� �������� �������� data (sData[i]) ������������ ��� STable[data[i]], ��� �������
* �������� data[i] ��������� � ���� ������� ������ �������� sData[i].
* ������� ������������ � ������������ ������.
*
* \param [in] data � �������� ������� ������������������ ���� ������� 16.
* \return ���������� ��������� ��������������� ������� ������������������.
*/
vector<uint8_t> gost12_15::STransformation(vector<uint8_t> data) {
    vector<uint8_t> sData(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        sData[i] = STable[data[i]];
    }

    return sData;
}


/**
* \brief ������� ��������� ����������� ��������������.
*
* � ������� ����� ����������� �������� ���������� �����������, ���������� �������� inverseSTable.
* ����� �������� �������� data (sData[i]) ������������ ��� inverseSTable[data[i]], ��� �������
* �������� data[i] ��������� � ���� ������� ������ �������� sData[i].
* ������� ������������ � ������������� ������.
*
* \param [in] data � ������������� ������� ������������������ ���� ������� 16.
* \return ���������� �������������� ������� ���������������.
*/
vector<uint8_t> gost12_15::inverseSTransformation(vector<uint8_t> data) {
    vector<uint8_t> sData(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        sData[i] = inverseSTable[data[i]];
    }

    return sData;
}


/**
* \brief ������� X ��������������.
*
* ������� ������������ ����� ������������ �������� �� ������ 2, ��� xor.
* ��������� xor ������� ��� ����, ������� ������������ ��� ������������ � ������������� ������.
* ������ ������� ����������� � ��������� ��������� ����� �� ������� ������������������.
*
* \param [in] data � ������� ������������������ ���� ������� 16.
* \param [in] key - ��������� ���� ������� 16 ����.
* \return ���������� ��������� ��������� ���������� ����� �� ������� ������������������.
*/
vector<uint8_t> gost12_15::XTransformation(vector<uint8_t> data, vector<uint8_t> key) {
    vector<uint8_t> dataX(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        dataX[i] = data[i] ^ key[i];
    }

    return dataX;
}


/**
* \brief ������� ������������� ��������� ������ � ��������.
*
* � ������� ���������� ����������� ������ ��� ������ ��������� ������, ������ �� �������
* ����� ������ 16 ���� (������� 10 �� 16).
* ��� �� ���������� ������ ��� �������� ���� ��������� ��������, ������ �� ������� �����
* ������ 16 ���� (������� 32 �� 16).
* ������� ���������� ���� ��� ��� ������ ���������, �.�. ��������� ������ ��������������
* ���������� ��� ������� ����� ��������� ������.
*
*/
void gost12_15::initRoundConsts() {
    for (size_t i = 0; i < roundConsts.size(); i++) {
        for (size_t j = 0; j < roundConsts[i].size(); j++) {
            roundConsts[i][j] = 0;
        }
    }

    this->roundConsts.resize(32);
    for (size_t i = 0; i < roundConsts.size(); i++) {
        this->roundConsts[i].resize(blockSize);
        this->roundConsts[i][blockSize - 1] = static_cast<uint8_t>(i + 1);
        this->roundConsts[i] = inverseData(this->roundConsts[i]);
        this->roundConsts[i] = LTransformation(this->roundConsts[i]);
        this->roundConsts[i] = inverseData(this->roundConsts[i]);
    }
}


/**
* \brief ������� ��������� ��������� ���������� (��������� ��������� ������).
*
* ��� ������������ � ������������� ��������� ������ ��������� ������, � ��� �� ��������� ����������
* �������� ��� ��������� ���������, ������� ���������� �� ����������� ������ �������� � �������
* ��������� ��������������.
* ��������� ��������� �������������� � ������� ������� initConstsAndRoundKeys ��� ������ ���������.
*
* ������ ��� ��������� ����� k1 � k2 ���������� ���������� ��������� ����� key �� ��� �����.
* ����� ��� ��������� ������ ���� ��������� ������ ������������ 8-��������� �������� �� ���������� ��������,
* � ������� ������� ���������� �������������� ������������ ��� ������������������ �������������� LSX,
* � � �������� ��������� ������ ������������ ��������� ���������.
*
* \param [in] key � ������� ���� ������ 32 �����.
* \return ���������� ������� ��������� ������ ������� 10 (���������� ������) �� 16 (������ �����).
*/
vector<vector<uint8_t>> gost12_15::generatingRoundKeys(vector<uint8_t> key) {
    vector<vector<uint8_t>> roundKeys;
    roundKeys.resize(10);
    for (size_t i = 0; i < roundKeys.size(); i++) {
        roundKeys[i].resize(blockSize);
    }

    for (int i = 0; i < blockSize; i++) {
        roundKeys[0][i] = key[i];
    }

    for (int i = 0; i < blockSize; i++) {
        roundKeys[1][i] = key[i + blockSize];
    }

    vector<uint8_t> k1 = roundKeys[0];
    vector<uint8_t> k2 = roundKeys[1];
    vector<uint8_t> lsx(blockSize, 0);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            if (j % 2 == 0) {
                lsx = XTransformation(k1, roundConsts[8 * i + j]);
                lsx = inverseData(lsx);
                lsx = STransformation(lsx);
                lsx = LTransformation(lsx);
                lsx = inverseData(lsx);
                k2 = dataXor(lsx, k2);
            }
            else if (j % 2 == 1) {
                lsx = XTransformation(k2, roundConsts[8 * i + j]);
                lsx = inverseData(lsx);
                lsx = STransformation(lsx);
                lsx = LTransformation(lsx);
                lsx = inverseData(lsx);
                k1 = dataXor(lsx, k1);
            }
        }
        roundKeys[i * 2 + 2] = k1;
        roundKeys[i * 2 + 3] = k2;
    }

    return roundKeys;
}


/**
* \brief ������� LSX ��������������.
*
* �������� ������� ������������������ �������� 9 ������� LSX ��������������.
* �� ��������� 10� ������ ���������� ��������� ��������� ���������� �����.
*
* \param [in] data � �������� ������� ������������������ ������� 16 ����.
* \param [in] roundKeys - ������� ��������� ������.
* \return ���������� ��������� �������������� LSX ��� �������� ������������������.
*/
vector<uint8_t> gost12_15::LSXEncryptData(vector<uint8_t> data, vector<vector<uint8_t>> roundKeys) {
    vector<uint8_t> encData = data;

    for (int i = 0; i < 9; i++) {
        encData = LSXTransformation(encData, roundKeys[i]);
    }

    encData = XTransformation(encData, roundKeys[9]);

    return encData;
}


/**
* \brief ������� ��������� LSX ��������������.
*
* �������� ������� ������������������ �������� 9 ������� ��������� LSX ��������������.
* �� ��������� 10� ������ ���������� ��������� ��������� ���������� �����.
* ����� ������� � �������� �������, �� ���������� � �������.
*
* \param [in] data � ������������� ������� ��������������� ������� 16 ����.
* \param [in] roundKeys - ������� ��������� ������.
* \return ���������� ��������� ��������� LSX �������������� ��� �������� ������������������.
*/
vector<uint8_t> gost12_15::LSXDecryptData(vector<uint8_t> data, vector<vector<uint8_t>> roundKeys) {
    vector<uint8_t> decData = data;

    for (int i = 9; i > 0; i--) {
        decData = inverseLSXTransformation(decData, roundKeys[i]);
    }

    decData = XTransformation(decData, roundKeys[0]);

    return decData;
}


/**
* \brief ������� ������ ������ LSX ��������������.
*
* ���� ����� LSX �������������� �������� � ����:
* 1. ��������� ��������� ���������� ����� �� �������� ������������������ (XTransformation).
* 2. ���������� �������������� (STransformation).
* 3. �������� �������������� (LTransformation).
*
* \remark ��������� � ��������� �������� ������������������ ���������� � ������� ����� (������),
* ��������� ����������� �������� (inverseData) �������� ������������������, �.�. �� ���� ��� ��������
* � ���������� �� ������� ����� (�����).
*
* \param [in] data � �������� ������������������ ������� 16 ����.
* \param [in] roundKey - ��������� ���� ������� 16 ����.
* \return ���������� ��������� ������ ������ LSX ��������������.
*/
vector<uint8_t> gost12_15::LSXTransformation(vector<uint8_t> data, vector<uint8_t> roundKey) {
    vector<uint8_t> lsxData = data;

    lsxData = XTransformation(lsxData, roundKey);
    lsxData = inverseData(lsxData);

    lsxData = STransformation(lsxData);
    lsxData = LTransformation(lsxData);
    lsxData = inverseData(lsxData);

    return lsxData;
}


/**
* \brief ������� ������ ������ ��������� LSX ��������������.
*
* ���� ����� ��������� LSX �������������� �������� � ����:
* 1. ��������� ��������� ���������� ����� �� �������� ������������������ (XTransformation).
* 2. �������� �������� �������������� (inverseSTransformation).
* 3. �������� ���������� �������������� (inverseLTransformation).
*
* \remark ��������� � ��������� �������� ������������������ ���������� � ������� ����� (������),
* ��������� ����������� �������� (������) �������� ������������������, �.�. �� ���� ��� ��������
* � ���������� �� ������� ����� (�����).
*
* \param [in] data � �������� ������������������ ������� 16 ����.
* \param [in] roundKey - ��������� ���� ������� 16 ����.
* \return ���������� ��������� ������ ������ ��������� LSX ��������������.
*/
vector<uint8_t> gost12_15::inverseLSXTransformation(vector<uint8_t> data, vector<uint8_t> roundKey) {
    vector<uint8_t> lsxDataInv = data;

    lsxDataInv = XTransformation(lsxDataInv, roundKey);
    lsxDataInv = inverseData(lsxDataInv);

    lsxDataInv = inverseLTransformation(lsxDataInv);
    lsxDataInv = inverseSTransformation(lsxDataInv);
    lsxDataInv = inverseData(lsxDataInv);

    return lsxDataInv;
}


/**
* \brief ������� ���������� �������� �� ������ 2 (xor).
*
* \param [in] data1 � ������ ������.
* \param [in] data2 � ������ ������.
* \return ���������� ��������� ���������� �������� �� ������ 2 ���� ��������.
*/
vector<uint8_t> gost12_15::dataXor(vector<uint8_t> data1, vector<uint8_t> data2) {
    vector<uint8_t> dataXor(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        dataXor[i] = data1[i] ^ data2[i];
    }

    return dataXor;
}


/**
* \brief ������� ������������� ��������� ���� ����������� � �������� ����.
*
* \param [in] binPolynom1 � ������ ��������� � �������� ����.
* \param [in] binPolynom1 � ������ ��������� � �������� ����.
* \return ���������� ��������� ��������� ���� ����������� � �������� ����.
*/
vector<uint8_t> gost12_15::polynomMult(vector<uint8_t> binPolynom1, vector<uint8_t> binPolynom2) {
    vector<uint8_t> binMultRes(binPolynom1.size() + binPolynom2.size(), 0);

    for (size_t i = 0; i < binPolynom1.size(); i++) {
        for (size_t j = 0; j < binPolynom2.size(); j++) {
            binMultRes[i + j + 1] = static_cast<uint8_t>(binMultRes[i + j + 1] ^ (binPolynom1[i] & binPolynom2[j]));
        }
    }

    return binMultRes;
}


/**
* \brief ������� ��������� ��������� ������������� ����� � �������.
*
* \param [in] number � ����� � ���������� �������������.
* \return ���������� ������ ��������� ������������� ��������� �����.
*/
vector<uint8_t> gost12_15::getBinaryVector(uint8_t number) {
    vector<uint8_t> binNumber(8, 0);
    bitset<8> binSeq = bitset<8>(number);

    for (size_t i = 0; i < binNumber.size(); i++) {
        binNumber[i] = binSeq[binNumber.size() - i - 1];
    }

    return binNumber;
}


/**
* \brief ������� ��������� ������� ������������������.
*
* \param [in] data � �������� ������������������.
* \return ���������� ����������� �������� ������������������.
*/
vector<uint8_t> gost12_15::inverseData(vector<uint8_t> data) {
    vector<uint8_t> invData(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        invData[i] = data[blockSize - i - 1];
    }

    return invData;
}

/**
 * \brief ���������� ��� ������� ����� ���� � ������. ������� �������� ����: ������� ������ � �����.
 * \details ����� ������ ���� �������� � ������. � ������ ��� ��������� ���������� ������ �������.
 * \details ������� ����� ������-�� � ��������� ���������, �� ��������� �� ������������.
 * \details ToDo: �� ����� ������ �������� ������ � ����� ������� ���������, � ������� � ������. ��� ������� ����� �������� � ������������.
 * \details ToDo: �������� ��-���� ����������� ��� ������ � ������� �� C++-���.
 * \param [in] a ��������� �� ������� ������, � ������� �������� ������ ���������.
 * \param [in] sizeA ����� � ������ ������� ����������.
 * \param [in] b ��������� �� ������� ������, � ������� �������� ������ ���������.
 * \param [in] sizeB ����� � ������ ������� ����������.
 * \param [out] sum ��������� �� ��������� �� ������� ������, � ������� ������� ���������.
 * \return ����� ����������.
 */
unsigned gost12_15::longAddition(unsigned char* a, unsigned sizeA,
                      unsigned char* b, unsigned sizeB,
                      unsigned char** sum)
{
    unsigned lengthResult;
    if (sizeA > sizeB)
        lengthResult = sizeA + 1;
    else
        lengthResult = sizeB + 1;

    const auto tmpSum = static_cast<unsigned char*>(calloc(lengthResult, 1));
    const auto shiftA = static_cast<unsigned char*>(calloc(lengthResult, 1));
    memcpy(shiftA + lengthResult - sizeA, a, sizeA);
    const auto shiftB = static_cast<unsigned char*>(calloc(lengthResult, 1));
    memcpy(shiftB + lengthResult - sizeB, b, sizeB);

    for (unsigned i = lengthResult - 1; i >= 1; --i)
    {
        const unsigned short tmpAddition = static_cast<unsigned short>(shiftA[i]) +
                                           static_cast<unsigned short>(shiftB[i]) +
                                           static_cast<unsigned short>(tmpSum[i]); // ��������� ��������� ������� ����� � ����������� ������ �� ����������� ��������
        tmpSum[i] = tmpAddition % 256; // ���� ���� ������ ��� �������� �� ����������
        tmpSum[i - 1] += (tmpAddition / 256); // ���� ���� ������ ��� ��������, ��������� ��� � ��������� ��������
    }

    if (tmpSum[0] == 0)
    {
        --lengthResult;
        *sum = static_cast<unsigned char*>(calloc(lengthResult, 1));
        memcpy(*sum, tmpSum + 1, lengthResult);
    }
    else
    {
        *sum = static_cast<unsigned char*>(calloc(lengthResult, 1));
        memcpy(*sum, tmpSum, lengthResult);
    }
    free(tmpSum);
    free(shiftA);
    free(shiftB);
    return lengthResult;
}

/**
 * \brief �++-style ��������� ��� ������� �������� ������� �����. ������� �������� ����: ������� ������ � �����.
 * @param a ������ ���������.
 * @param b ������ ���������.
 * @return �����.
 */
std::vector<uint8_t> gost12_15::longAddition(std::vector<uint8_t> a, std::vector<uint8_t> b)
{
    unsigned char* sum;
    auto length = longAddition(a.data(), a.size(), b.data(), b.size(), &sum);
    std::vector<uint8_t> result(sum, sum + length);
    free(sum);
    return result;
}

/**
* \brief ������� ������ ������������.
*
* �������������� � ��������������� ������ � ������ ������������.
* �������� �������� (gammaSync) - ���������� ������������� ����������� ������ �� ������� �����,
* �� �� ��������� ����� �������� �������� ��������, ������ ������ �������� (������� � 1).
* ��� ������� ����� �������� ������������������, gammaSync ��������� � ������� LSX ��������������.
* ����� ������������� gammaSync �������� ������������� �� �������� �������� �����.
*
* \param [in] data � �������� ��������������� ��������� ������.
* \param [in] sync � �������������.
* \param [in] roundKeys - ������� ��������� ������.
* \return ���������� ������ ������ ������������ - ������������� (��������������) �������� ������������������.
*/
vector<uint8_t> gost12_15::gammaCryption(vector<uint8_t> data, vector<uint8_t> sync, vector<vector<uint8_t>> roundKeys) {
    vector<uint8_t> gammaSync(blockSize, 0);
    for (int i = 0; i < blockSize / 2; i++) {
        gammaSync[i] = sync[i];
    }

    int blockCount = static_cast<int>(data.size() / blockSize);

    vector<uint8_t> encSync;
    vector<uint8_t> encData(blockCount*blockSize, 0);
    for (int i = 0; i < blockCount; i++) {
        encSync = gammaSync;

        encSync = LSXEncryptData(encSync, roundKeys);

        for (int j = 0; j < blockSize; j++) {
            encData[blockSize*i + j] = data[blockSize*i + j] ^ encSync[j];
        }

        gammaSync = longAddition(gammaSync, {0x01});
        if(gammaSync.size() > blockSize) { // ���� �������� ��������� �����, �� ��������.
            gammaSync.erase(gammaSync.begin());
        }
    }

    return encData;
}


/**
* \brief ������� ��������� ������������.
*
* ��������� ���������� ������������ ����������� ��������� �������: �� ������ ���� ��������� ��������� XOR
* ����� ������� ��������� ������������ � ��������������� ������ ��������� ����. �� ��������� �����,
* ����� ����������� ���������� ������� XOR � ������ ������������. ����� �����, �� ������������ �������
* ������ �������� �������������� ������.
*
* \param [in] data � �������� ��������������� ��������� ������.
* \param [in] roundKeys - ������� ��������� ������.
* \return ���������� ����������� ������������.
*/
vector<uint8_t> gost12_15::imitoGeneration(vector<uint8_t> data, vector<vector<uint8_t>> roundKeys) {
    vector<uint8_t> imito(imitoLen, 0);
    vector<uint8_t> blockData(blockSize, 0);
    int blockCount = static_cast<int>(data.size() / blockSize);

    for (int j = 0; j < blockSize; j++) {
        blockData[j] = data[j];
    }

    blockData = LSXEncryptData(blockData, roundKeys);

    for (int i = 1; i < blockCount - 1; i++) {
        for (int j = 0; j < blockSize; j++) {
            blockData[j] = blockData[j] ^ data[i*blockSize + j];
        }

        blockData = LSXEncryptData(blockData, roundKeys);
    }

    vector<uint8_t> imitoKey = getImitoKey(roundKeys);
    for (int j = 0; j < blockSize; j++) {
        blockData[j] = blockData[j] ^ data[(blockCount - 1)*blockSize + j];
        blockData[j] = blockData[j] ^ imitoKey[j];
    }

    blockData = LSXEncryptData(blockData, roundKeys);

    for (int i = 0; i < imitoLen; i++) {
        imito[i] = blockData[i];
    }

    return imito;
}


/**
* \brief ������� ��������� ����� ��� ������������.
*
* ��� ������ ��������� ������� ������������������ ������� 16 ����. ����������� ����� �������� ���� imitoKey.
* ���� � ���������� ������ ���� ����� imitoKey ����� ����, �� ����������� �������� ���� imitoKey,
* �������� ��������� �� ������� �����.
* � ��������� ������, ����������� �������� XOR ����� imitoKey, �������� ���������� �� ������� �����, � ���������
* �128.
*
* \param [in] roundKeys - ������� ��������� ������.
* \return ���������� ����������� ���� ��� ������������.
*/
vector<uint8_t> gost12_15::getImitoKey(vector<vector<uint8_t>> roundKeys) {
    vector<uint8_t> imitoKey(blockSize, 0);
    uint8_t overflowFlag;
    uint8_t overflow = 0;

    imitoKey = LSXEncryptData(imitoKey, roundKeys);

    for (int i = blockSize - 1; i >= 0; i--) {
        overflowFlag = imitoKey[i] < 0x80 ? 0 : 1;
        imitoKey[i] = static_cast<uint8_t>(imitoKey[i] * 0x02 + overflow);
        overflow = overflowFlag;
    }

    if (imitoKey[blockSize - 1] != 0) {
        for (int i = 0; i < blockSize; i++) {
            imitoKey[i] = imitoKey[i] ^ B128[i];
        }
    }

    return imitoKey;
}