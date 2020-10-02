#include <cstring>

#include "gost12_15.h"


/**
* \brief Функция умножения чисел в конечном поле над неприводимым полиномом.
*
* Умножение происходит над полем Галуа GF(2^8) над неприводимым полиномом x^8 + x^7 + x^6 + x + 1.
* Суть функции в умножении в столбик с добавлением числа 0xс3, которое и представляет нужный нам полином.
*
* \param [in] polynom1 – первый многочлен для умножения.
* \param [in] polynom2 – второй многочлен для умножения.
* \return возвращает результат умножения двух многочленов.
*/
uint8_t gost12_15::galoisMult(uint8_t polynom1, uint8_t polynom2) {
    uint8_t multRes = 0;
    uint8_t highBit;

    for (int i = 0; i < 8; i++) {
        if (polynom2 & 1) {
            multRes = multRes ^ polynom1;
        }

        highBit = polynom1 & 0x80; //запомнить старший бит
        polynom1 = static_cast<uint8_t>(polynom1 << 1);

        if (highBit) {
            polynom1 = polynom1 ^ this->generatingPolynom; // Порождающий полином вычитается из polynom1
        }

        polynom2 = static_cast<uint8_t>(polynom2 >> 1);
    }

    return multRes;
}


/**
* \brief Функция умножения байтовой последовательности на коэффициенты l функции.
*
* Каждый байт из блока умножается с помощью функции galoisMult на один из коэффициентов из ряда lCoefficients
* в зависимости от порядкового номера байта. Байты складываются между собой по модулю 2 (xor).
* Операция xor является сложением над полем Галуа GT(2^8) с неприводимым многочленом x^8 + x^7 + x^6 + x + 1.
* Функция используется при шифровании.
*
* \param [in] data – открытая входная последовательность байт размера 16.
* \return возвращает полином 7-й степени, который представлен в числовом виде.
*/
uint8_t gost12_15::lFunc(vector<uint8_t> data) {
    uint8_t la = 0;

    for (int i = 0; i < blockSize; i++) {
        la = la ^ galoisMult(data[i], lCoefficients[i]);
    }

    return la;
}


/**
* \brief Функция обратная к lFunc.
*
* В функции также каждый байт из блока умножается с помощью функции galoisMult на один из коэффициентов
* из ряда lCoefficients, но порядок этих коэффициентов изменен.
* Функция используется в алгоритме расшифрования.
*
* \param [in] data – зашифрованная входная последовательность байт размера 16.
* \return возвращает полином 7-й степени, который представлен в числовом виде.
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
* \brief Функция линейного преобразования.
*
* Линейное перемешивание L шифра «Кузнечик» может быть описано с помощью линейного регистра сдвига R:
* 1. Для каждого байта из шестнадцати байт блока входной последовательности вычисляется функция lFunc(data).
* 2. Полученный на предыдущем шаге результат записывается первым в строку байтов, затем записываются все байты
*    входной последовательности data, кроме младшего (последнего) .
* Таким образом, фактически производится сдвиг строки байтов а вправо на один байт.
* Цикл выполняется 16 раз, функция используется при зашифровании данных.
*
* \param [in] data – открытая входная последовательность байт размера 16.
* \return возвращает линейно преобразованную входную последовательность .
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
* \brief Функция обратного линейного преобразования.
*
* 1. Для каждого байта из шестнадцати байт блока входной последовательности вычисляется функция inverselFunc(data).
* 2. Полученный на предыдущем шаге результат записывается последним в строку байтов, затем записываются все байты
*    входной последовательности data, кроме старшего (первого).
* Цикл выполняется 16 раз, функция используется при расшифровании данных.
*
* \param [in] data – зашифрованная входная последовательность байт размера 16.
* \return возвращает расшифрованную входную последовательность.
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
* \brief Функция нелинейного преобразования.
*
* Нелинейное S преобразовании в алгоритме выполняется через замену.
* К каждому байту применяется нелинейная подстановка, задаваемая массивом STable.
* Новое значение элемента data (sData[i]) определяется как STable[data[i]], где текущее
* значение data[i] выступает в роли индекса нового значения sData[i].
* Функция используется в зашифровании данных.
*
* \param [in] data – открытая входная последовательность байт размера 16.
* \return возвращает нелинейно преобразованную входную последовательность.
*/
vector<uint8_t> gost12_15::STransformation(vector<uint8_t> data) {
    vector<uint8_t> sData(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        sData[i] = STable[data[i]];
    }

    return sData;
}


/**
* \brief Функция обратного нелинейного преобразования.
*
* К каждому байту применяется обратная нелинейная подстановка, задаваемая массивом inverseSTable.
* Новое значение элемента data (sData[i]) определяется как inverseSTable[data[i]], где текущее
* значение data[i] выступает в роли индекса нового значения sData[i].
* Функция используется в расшифровании данных.
*
* \param [in] data – зашифрованная входная последовательность байт размера 16.
* \return возвращает расшифрованную входную последовательно.
*/
vector<uint8_t> gost12_15::inverseSTransformation(vector<uint8_t> data) {
    vector<uint8_t> sData(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        sData[i] = inverseSTable[data[i]];
    }

    return sData;
}


/**
* \brief Функция X преобразования.
*
* Функция представляет собой классическое сложение по модулю 2, или xor.
* Поскольку xor обратен сам себе, функция используется для зашифрования и расшифрования данных.
* Логика функции заключается в побитовом наложении ключа на входную последовательность.
*
* \param [in] data – входная последовательность байт размера 16.
* \param [in] key - раундовый ключ размера 16 байт.
* \return возвращает результат наложения раундового ключа на входную последовательность.
*/
vector<uint8_t> gost12_15::XTransformation(vector<uint8_t> data, vector<uint8_t> key) {
    vector<uint8_t> dataX(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        dataX[i] = data[i] ^ key[i];
    }

    return dataX;
}


/**
* \brief Функция инициализации раундовых ключей и констант.
*
* В функции выделяется необходимая память для десяти раундовых ключей, каждый из которых
* имеет размер 16 байт (матрица 10 на 16).
* Так же выделяется память для тридцати двух раундовых констант, каждая из которых имеет
* размер 16 байт (матрица 32 на 16).
* Функция вызывается один раз при старте программы, т.к. константы всегда вырабатываются
* идентичные для каждого этапа развертки ключей.
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
* \brief Функция генерации ключевого расписания (выработка раундовых ключей).
*
* Для зашифрования и расшифрования требуется десять раундовых ключей, а для их получения необходимы
* тридцать две раундовые константы, которые получаются из порядкового номера итерации с помощью
* линейного преобразования.
* Раундовые константы вырабатываются с помощью функции initConstsAndRoundKeys при старте программы.
*
* Первые два раундовых ключа k1 и k2 получаются разбиением исходного ключа key на две части.
* Далее для выработки каждой пары раундовых ключей используется 8-раундовый алгоритм со структурой Фейстеля,
* в котором функция раундового преобразования определяется как последовательность преобразований LSX,
* а в качестве раундовых ключей используются раундовые константы.
*
* \param [in] key – главный ключ длиной 32 байта.
* \return возвращает матрицу раундовых ключей размера 10 (количество ключей) на 16 (размер блока).
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
* \brief Функция LSX преобразования.
*
* Открытая входная последовательность проходит 9 раундов LSX преобразования.
* На последнем 10м раунде происходит побитовое наложение раундового ключа.
*
* \param [in] data – открытая входная последовательность размера 16 байт.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает результат преобразования LSX для исходной последовательности.
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
* \brief Функция обратного LSX преобразования.
*
* Открытая входная последовательность проходит 9 раундов обратного LSX преобразования.
* На последнем 10м раунде происходит побитовое наложение раундового ключа.
* Ключи следуют в обратном порядке, от последнего к первому.
*
* \param [in] data – зашифрованная входная последовательно размера 16 байт.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает результат обратного LSX преобразования для исходной последовательности.
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
* \brief Функция одного раунда LSX преобразования.
*
* Один раунд LSX преобразования включает в себя:
* 1. Побитовое наложение раундового ключа на исходную последовательность (XTransformation).
* 2. Нелинейное преобразование (STransformation).
* 3. Линейное преобразование (LTransformation).
*
* \remark Поскольку в алгоритме исходная последовательность нумеруется с младших битов (справа),
* требуется производить разворот (inverseData) исходной последовательности, т.к. на вход она подается
* с нумерацией со старших битов (слева).
*
* \param [in] data – исходная последовательность размера 16 байт.
* \param [in] roundKey - раундовый ключ размера 16 байт.
* \return возвращает результат одного раунда LSX преобразования.
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
* \brief Функция одного раунда обратного LSX преобразования.
*
* Один раунд обратного LSX преобразования включает в себя:
* 1. Побитовое наложение раундового ключа на исходную последовательность (XTransformation).
* 2. Обратное линейное преобразование (inverseSTransformation).
* 3. Обратное нелинейное преобразование (inverseLTransformation).
*
* \remark Поскольку в алгоритме исходная последовательность нумеруется с младших битов (справа),
* требуется производить разворот (реверс) исходной последовательности, т.к. на вход она подается
* с нумерацией со старших битов (слева).
*
* \param [in] data – исходная последовательность размера 16 байт.
* \param [in] roundKey - раундовый ключ размера 16 байт.
* \return возвращает результат одного раунда обратного LSX преобразования.
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
* \brief Функция побитового сложения по модулю 2 (xor).
*
* \param [in] data1 – первый вектор.
* \param [in] data2 – второй вектор.
* \return возвращает результат побитового сложения по модулю 2 двух векторов.
*/
vector<uint8_t> gost12_15::dataXor(vector<uint8_t> data1, vector<uint8_t> data2) {
    vector<uint8_t> dataXor(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        dataXor[i] = data1[i] ^ data2[i];
    }

    return dataXor;
}


/**
* \brief Функция классического умножения двух многочленов в бинарном виде.
*
* \param [in] binPolynom1 – первый многочлен в бинарном виде.
* \param [in] binPolynom1 – второй многочлен в бинарном виде.
* \return возвращает результат умножения двух многочленов в бинарном виде.
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
* \brief Функция получения бинарного представления числа в векторе.
*
* \param [in] number – число в десятичном представлении.
* \return возвращает вектор двоичного представления исходного числа.
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
* \brief Функция разворота входной последовательности.
*
* \param [in] data – исходная последовательность.
* \return возвращает развернутую исходную последовательность.
*/
vector<uint8_t> gost12_15::inverseData(vector<uint8_t> data) {
    vector<uint8_t> invData(blockSize, 0);

    for (int i = 0; i < blockSize; i++) {
        invData[i] = data[blockSize - i - 1];
    }

    return invData;
}

/**
 * \brief Складывает два длинных числа друг с другом. Порядок хранения байт: младший разряд в конце.
 * \details Числа должны быть записаны в памяти. А память под результат выделяется внутри функции.
 * \details Функция взята откуда-то с просторов интернета, но проверена на корректность.
 * \details ToDo: Не очень хорошо выделять память в одной области видимости, а очищать в другой. Эту функцию стоит обдумать и переработать.
 * \details ToDo: Поменять Си-шные инструменты для работы с памятью на C++-ные.
 * \param [in] a Указатель на область памяти, в которой хранится первое слагаемое.
 * \param [in] sizeA Длина в байтах первого слагаемого.
 * \param [in] b Указатель на область памяти, в которой хранится второе слагаемое.
 * \param [in] sizeB Длина в байтах второго слагаемого.
 * \param [out] sum Указатель на указатель на область памяти, в которой сохранён результат.
 * \return Длина результата.
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
                                           static_cast<unsigned short>(tmpSum[i]); // суммируем последние разряды чисел и перенесённый разряд из предыдущего сложения
        tmpSum[i] = tmpAddition % 256; // если есть разряд для переноса он отсекается
        tmpSum[i - 1] += (tmpAddition / 256); // если есть разряд для переноса, переносим его в следующее сложение
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
 * \brief С++-style интерфейс для функции сложения длинных чисел. Порядок хранения байт: младший разряд в конце.
 * @param a Первое слагаемое.
 * @param b Второе слагаемое.
 * @return Сумма.
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
* \brief Функция режима гаммирования.
*
* Зашифровывание и расшифровывание данных в режиме гаммирования.
* Исходное значение (gammaSync) - уникальная синхропосылка дополняется нулями до размера блока,
* но на последнем место ставится значение счётчика, равное номеру итерации (начиная с 1).
* Для каждого блока исходной последовательности, gammaSync шифруется с помощью LSX преобразования.
* Затем зашифрованная gammaSync побитово накладывается на открытый исходный текст.
*
* \param [in] data – исходная последовательно открытого текста.
* \param [in] sync – синхропосылка.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает работы режима гаммирования - зашифрованную (расшифрованную) исходную последовательность.
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
        if(gammaSync.size() > blockSize) { // Если сложение увеличило длину, то обрезаем.
            gammaSync.erase(gammaSync.begin());
        }
    }

    return encData;
}


/**
* \brief Функция выработки имитовставки.
*
* Процедура вычисления имитовставки описывается следующим образом: на каждом шаге шифруется побитовый XOR
* между текущим значением имитовставки и соответствующим блоком исходного кода. На последнем этапе,
* перед шифрованием необходимо сделать XOR с ключом имитовставки. После этого, за имитовставку берется
* первая половина зашифрованного текста.
*
* \param [in] data – исходная последовательно открытого текста.
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает вычисленную имитовставку.
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
* \brief Функция выработки ключа для имитовставки.
*
* Для начала шифруется нулевая последовательность размера 16 байт. Результатом будет являться блок imitoKey.
* Если в результате первый байт блока imitoKey равен нулю, то результатом является блок imitoKey,
* побитово сдвинутый на единицу влево.
* В противном случае, результатом является XOR блока imitoKey, побитово сдвинутого на единицу влево, и константы
* В128.
*
* \param [in] roundKeys - матрица раундовых ключей.
* \return возвращает вычисленный ключ для имитовставки.
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