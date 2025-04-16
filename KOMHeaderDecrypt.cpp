/*
 * Copyright © [2025] YuilMui
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "Extractor.h"
#include "Util.h"

using byte = unsigned char;

void DecryptionHelper::SetHeaderKeys(vector<uint>& HeaderKeys, uint FileSize)
{
	//Filesize is the seed
	auto startIndex = (static_cast<ulong>(12u) * (FileSize % 0xC8u) + 12u) / sizeof(uint);

	for (int i = 0; i < 3; i++)
		HeaderKeys.push_back(MappedHeaderKeys[startIndex++]);
}

void DecryptionHelper::HeaderDecryptV4(string& EncryptedXML, string& DecryptedXML, vector<uint>& HeaderKeys)
{
    int count = 0;		   //Count until encrypted XML is empty
    int KeyAreaCnt = 0;    //Index of encryption header key used
    unsigned int* pointer; //pointer for encrypted xml
    unsigned int buffer = 0; //temporary 4 byte buffer when XOR decrypting 4 bytes at a time

    DecryptedXML.resize(EncryptedXML.size()); //Resize DecryptedXML string size

    while (count < EncryptedXML.size())
    {
        if (KeyAreaCnt >= HeaderKeys.size())
            KeyAreaCnt = 0;

        pointer = (unsigned int*)&EncryptedXML[count]; //point to encrypted XML
        buffer = *pointer ^ HeaderKeys[KeyAreaCnt];	   //4 byte decrypted buffer(int)

        //Map int to the DecryptedXML string
        DecryptedXML[count++] = (buffer & 0x000000ff);
        DecryptedXML[count++] = (buffer & 0x0000ff00) >> 8;
        DecryptedXML[count++] = (buffer & 0x00ff0000) >> 16;
        DecryptedXML[count++] = (buffer & 0xff000000) >> 24;

        KeyAreaCnt++;
    }
}

void DecryptionHelper::HeaderDecrypt(string& EncryptedXML, string& DecryptedXML, vector<uint>& HeaderKeys, uint FileSize)
{
    // Initial seed calculation used for header decryption
    unsigned long long seed = 0;
    for(const int& key : HeaderKeys)
		seed += key;
    char data[0x20] = {0};
    sprintf_s(data, 0x20, "%u", seed);
    //std::cout << EncryptedXML << std::endl;

	CryptoPP::SHA1 sha1;
	// Digest array to store the result
	byte digest[CryptoPP::SHA1::DIGESTSIZE];

	// Step 1: Initialize the SHA-1 context
	sha1.Restart();

    // Step 2: Update the context with data
    sha1.Update((const byte*)data, strlen(data));

    // Step 3: Finalize the hash computation
    sha1.Final(digest);

    // Convert digest to a readable hex format
    CryptoPP::HexEncoder encoder;
    string output;
    encoder.Attach(new CryptoPP::StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    EncryptedXML.resize(FileSize - (FileSize & 7u));
    EncryptedXML = EncryptedXML.substr(0, FileSize - (FileSize & 7u));

    // Blowfish decryption in ECB mode using the SHA-1 digest as the key
    try 
    {
        CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Decryption decryptor;
        decryptor.SetKey(digest, CryptoPP::SHA1::DIGESTSIZE);

        CryptoPP::StringSource ss(EncryptedXML, true,
            new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::StringSink(DecryptedXML),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    }
    catch (const CryptoPP::Exception& e) 
    {
        cerr << "Decryption error: " << e.what() << std::endl;
        return;
    }

}