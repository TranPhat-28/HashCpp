/* Hash to string
h:{0,1}^* --> {0,1}^l, l is digest size */
#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring s2ws (const std::string& str);
string ws2s (const std::wstring& str);

#include "include/cryptopp/cryptlib.h"
#include "include/cryptopp/sha.h"
#include "include/cryptopp/sha3.h"
#include "include/cryptopp/shake.h"
#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
// input, output string
#include "include/cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::Redirector;
// input, output file
#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::byte;

#include <fstream>

void exeSHA224(wstring message);
void exeSHA256(wstring message);
void exeSHA384(wstring message);
void exeSHA512(wstring message);
void exeSHA3_224(wstring message);
void exeSHA3_256(wstring message);
void exeSHA3_384(wstring message);
void exeSHA3_512(wstring message);
void exeSHAKE128(wstring message, int d_input);
void exeSHAKE256(wstring message, int d_input);
string ReadFromFile(string filename);

int main (int argc, char* argv[])
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    // User input
    wcout << "Choose input source: " << endl << "1. From screen" << endl << "2. From file" << endl;
    int input;
    wcin >> input;
    std::wstring message;

    // Input from screen
    if (input == 1)
    {
        std::wcout << "Please input message" << std::endl;
        fflush(stdin);
        std::getline(std::wcin,message);
    }
    // Input from file
    else if (input == 2)
    {
        string msgFromfile = ReadFromFile("input.txt");
        message = s2ws(msgFromfile);
    }

    // User select hash function
    wcout << "Select HASH: " << endl << "1. SHA224" << endl << "2. SHA256" << endl << "3. SHA384" << endl << "4. SHA512" << endl;
    wcout << "5. SHA3-224" << endl << "6. SHA3-256" << endl << "7. SHA3-384" << endl << "8. SHA3-512" << endl;
    wcout << "9. SHAKE128" << endl << "10. SHAKE256" << endl;
    int selection;
    wcin >> selection;
    if (selection == 1)
    {
        exeSHA224(message);
    }
    else if (selection == 2)
    {
        exeSHA256(message);
    }
    else if (selection == 3)
    {
        exeSHA384(message);
    }
    else if (selection == 4)
    {
        exeSHA512(message);
    }
    else if (selection == 5)
    {
        exeSHA3_224(message);
    }
    else if (selection == 6)
    {
        exeSHA3_256(message);
    }
    else if (selection == 7)
    {
        exeSHA3_384(message);
    }
    else if (selection == 8)
    {
        exeSHA3_512(message);
    }
    else if (selection == 9)
    {
        wcout << "Choose digest size: " << endl << "1. Default digest size" << endl << "2. Input manually" << endl;
        int selection2;
        int d_input; // Digest size
        wcin >> selection2;
        if(selection2 == 1)
        {
            d_input = 0;
        }
        else if(selection2 == 2)
        {
            wcin >> d_input;
        }
        exeSHAKE128(message, d_input);
    }
    else if (selection == 10)
    {
        wcout << "Choose digest size: " << endl << "1. Default digest size" << endl << "2. Input manually" << endl;
        int selection2;
        int d_input; // Digest size
        wcin >> selection2;
        if(selection2 == 1)
        {
            d_input = 0;
        }
        else if(selection2 == 2)
        {
            wcin >> d_input;
        }
        exeSHAKE256(message, d_input);
    }
    else
    {
       wcout << "Invalid input";
       return 0;
    }
    return 0;
}

/* convert string to wstring */
wstring s2ws(const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string ws2s(const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void exeSHA224(wstring message)
{
    CryptoPP::SHA224 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}

void exeSHA256(wstring message)
{
    CryptoPP::SHA256 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}

void exeSHA384(wstring message)
{
    CryptoPP::SHA384 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}

void exeSHA512(wstring message)
{
    CryptoPP::SHA512 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}


void exeSHA3_224(wstring message)
{
    CryptoPP::SHA3_224 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}

void exeSHA3_256(wstring message)
{
    CryptoPP::SHA3_256 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}

void exeSHA3_384(wstring message)
{
    CryptoPP::SHA3_384 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}

void exeSHA3_512(wstring message)
{
    CryptoPP::SHA3_512 hash;

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();

    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
    //std::wcout << s2ws(encode) << std::endl;
}


void exeSHAKE128(wstring message, int d_input)
{
    CryptoPP::SHAKE128 hash;
    int d;
    // Default digest size
    if (d_input == 0)
    {
        d = hash.DigestSize();
    }
    else
    {
        d = d_input;
    }

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    //std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Digest size: " << d << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;

    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();
    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    //digest.resize(hash.DigestSize());
    digest.resize(d);
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;
}

void exeSHAKE256(wstring message, int d_input)
{
    CryptoPP::SHAKE256 hash;
    int d;
    // Default digest size
    if (d_input == 0)
    {
        d = hash.DigestSize();
    }
    else
    {
        d = d_input;
    }

    std::wcout << "Name: " << s2ws(hash.AlgorithmName()) << std::endl;
    //std::wcout << "Digest size: " << hash.DigestSize() << std::endl;
    std::wcout << "Digest size: " << d << std::endl;
    std::wcout << "Block size: " << hash.BlockSize() << std::endl;
    /*
    std::wstring message;
    std::wcout << "Please input message" << std::endl;
    fflush(stdin);
    std::getline(std::wcin,message);
    */
    // Compute disgest
    std::string digest;

    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;

    std::wcout << "Message: " << message << std::endl;

    std::string encode;
    for (int i = 0; i < 1000; i++)
    {
        start_time = clock();
    hash.Restart();
    hash.Update((const byte*)ws2s(message).data(), ws2s(message).size());
    //digest.resize(hash.DigestSize());
    digest.resize(d);
    hash.TruncatedFinal((byte*)&digest[0], digest.size());
    // Pretty print digest
    //std::wcout << "Message: " << message << std::endl;
    //std::wcout << "Digest: ";
    //std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    }
    std::wcout << "Digest: " <<  s2ws(encode) << std::endl;
    wcout << "Execution time: " << exec_time / 1000 << "ms" << endl;

}


// Read input from file
string ReadFromFile(string filename)
{
    string output;
    std::fstream my_file;
	my_file.open(filename, std::ios::in);
	/*if (!my_file) {
		output = "";
        return output;
	}
	else*/ 
    {
		char ch;
		while (1) {
			my_file >> ch;
			if (my_file.eof())
				break;
			output += ch;
		}
	}
	my_file.close();
    return output;
}