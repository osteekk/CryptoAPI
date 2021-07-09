#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include "installer.h"

using namespace std;

int main() {
// Запись программы в файл 
	string path, exepath;
	cout << "Enter the path to the folder where the program will be unpacked:\nExample: D:/Programs\nPath: ";
	cin >> path;
	exepath = path + "/STKB Lab 1.exe";
	ifstream in(exepath, ios::binary);
	if (in.is_open())
		cout << "File already exist!" << endl;
	else {
		cout << "Creating file..." << endl;
		int source_size = size(source);
		ofstream out(exepath, ios::binary | ios::app);
		for (int i = 0; i < source_size; i++) {
			out << char(source[i]);
		}
	}

// Собираем информацию о компьютере
	cout << "Collecting system data..." << endl << endl;
	string data[9] = {};
	char buffer[50];
	DWORD buf_size;
	buf_size = sizeof(buffer);
	GetUserName(buffer, &buf_size);
	data[0] = string(buffer);

	GetComputerName(buffer, &buf_size);
	data[1] = string(buffer);

	UINT usize = 50;
	GetWindowsDirectoryA(buffer, usize);
	data[2] = string(buffer);

	GetSystemDirectory(buffer, usize);
	data[3] = string(buffer);

	int key_type = GetKeyboardType(0);
	data[4] = to_string(key_type);

	int key_subtype = GetKeyboardType(1);
	data[5] = to_string(key_subtype);

	int screen_height = GetSystemMetrics(SM_CYSCREEN);
	data[6] = to_string(screen_height);

	MEMORYSTATUSEX lpBuffer;
	GlobalMemoryStatusEx(&lpBuffer);
	data[7] = to_string(lpBuffer.ullTotalPhys);

	char NameBuffer[MAX_PATH];
	char SysNameBuffer[MAX_PATH];
	DWORD VSNumber;
	DWORD MCLength;
	DWORD FileSF;

	if (GetVolumeInformation(NULL, NameBuffer, sizeof(NameBuffer), &VSNumber, &MCLength, &FileSF, SysNameBuffer, sizeof(SysNameBuffer)))
		data[8] = to_string(VSNumber);

	string collected_data = data[0] + " " + data[1] + " " + data[2] + " " + data[3] + " " + data[4] + " " + data[5] + " " + data[6] + " " + data[7] + " " + data[8];

// Хеширование и подпись
	cout << "Creating signature..." << endl;

	HCRYPTPROV hProv;
	HCRYPTKEY  hPublicKey;
	HCRYPTHASH hHash;

	// Получение контекста криптопровайдера
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL))
		cout << "CryptAcquireContext Error" << endl;
	else
		cout << "Cryptographic provider initialized" << endl;

	// Получение ключа для проверки цифровой подписи
	if (!CryptGetUserKey(hProv, AT_SIGNATURE, &hPublicKey))
		cout << "CryptGetUserKey Error" << endl;
	else
		cout << "Public key is received" << endl;

	// Cоздание хеш-объекта
	if (!CryptCreateHash(hProv, CALG_MD5, NULL, NULL, &hHash))
		cout << "CryptCreateHash Error" << endl;
	else
		cout << "Hash created" << endl;

	// Передача хешируемых данных хэш-объекту.
	DWORD data_size = collected_data.length() * sizeof(char);
	if (!CryptHashData(hHash, (BYTE*)collected_data.c_str(), data_size, NULL))
		cout << "CryptHashData Error" << endl;
	else
		cout << "Hash data loaded" << endl;

	// Получение значения хеша
	DWORD pdwDataLen;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &pdwDataLen, 0))
		cout << "Error while get hash value size" << endl;
	else
		cout << "Hash value size retrieved successful" << endl;

	BYTE* hash_value = (BYTE*)malloc(pdwDataLen);
	if (!CryptGetHashParam(hHash, HP_HASHVAL, hash_value, &pdwDataLen, 0))
		cout << "Error while get hash value" << endl;
	else
		cout << "Hash value retrieved successful" << endl;
	
	// Определение размера подписи
	DWORD n_size = 0;
	if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &n_size))
		cout << "CryptSignHash 1 Error!" << endl;
	else
		cout << "Signature length found: " << n_size << endl;

	// Выделение памяти для буфера подписи
	BYTE* sign_hash;
	if (!(sign_hash = (BYTE*)malloc(n_size)))
		cout << "Out of memory!" << endl;
	else
		cout << "Memory allocated for the signature" << endl;

	// Цифровая подпись хеш-значения
	if (!CryptSignHashA(hHash, AT_SIGNATURE, NULL, NULL, (BYTE*)sign_hash, &n_size))
		cout << "CryptSignHash 2 Error" << endl;
	else
		cout << "Signature created" << endl;

	// Проверка цифровой подписи
	BOOL result = CryptVerifySignature(hHash, (BYTE*)sign_hash, n_size, hPublicKey, NULL, 0);
	cout << "Check result: " << ((result) ? "Verified!" : "NOT verified!") << endl;
	cout << endl;

// Запись в HKEY_CURRENT_USER\Software\Sharuev\Signature
	cout << "Writting to registry..." << endl;

	HKEY hKeySert;

	// Создаем ключ в ветке HKEY_CURRENT_USER
	if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Sharuev\\", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKeySert, NULL) != ERROR_SUCCESS)
		cout << ("Error occurred while creating the key ") << endl;
	else 
		cout << ("Registry key created") << endl;

	// Пишем hash_value в созданный ключ
	if (RegSetValueEx(hKeySert, "Signature", 0, REG_BINARY, hash_value, pdwDataLen))
		cout << ("Error occurred while writing the string ") << endl;
	else
		cout << ("Registry key value successfuly set") << endl;

	// Закрываем описатель ключа
	if (RegCloseKey(hKeySert) != ERROR_SUCCESS)
		cout << ("Error occurred while closing the registry key ") << endl;
	else
		cout << ("Registry key closed") << endl;

// Уничтожение
	CryptDestroyHash(hHash);
	CryptDestroyKey(hPublicKey);
	CryptReleaseContext(hProv, NULL);

	cout << "\nInstallation completed successfully!\n" << endl;
	system("pause");
	return 0;
}