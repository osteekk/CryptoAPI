#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>

using namespace std;

string file_to_string();
void string_to_file(string new_file);
bool user_pass_check(string pass_to_check);

class Guest {
public:
	char menu() {
		string choise;
		Guest guest;

		cout << "You have a \"Guest tier\". Login for more priviliges!" << endl;
		cout << "Enter \"help\" to get a list of commands " << endl << endl;

		while (1) {
			cout << "guest@guest:~$ ";
			cin >> choise;
			if (choise == "login")
				return guest.login();
			else if (choise == "about")
				guest.about();
			else if (choise == "help")
				guest.help();
			else if (choise == "exit")
				return 'e';
			else
				cout << "Command not found! Pleace, try again" << endl;
		}
	}
protected:
	static string username, pass, block, constr;
	static void set_user(string input_username, string input_pass, string input_block, string input_constr) {
		{
			Guest::username = input_username;
			Guest::pass = input_pass;
			Guest::block = input_block;
			Guest::constr = input_constr;
		}
	}
	char login() {
		ifstream in("users.txt", ios::binary);
		if (!in.is_open()) {
			cout << "File Open Error!" << endl;
			return 'g';
		}
		else {
			string file_data = file_to_string();
			string input_username, input_pass;

			for (int i = 0; i < 3; i++) {
				cout << "Login: ";
				cin >> input_username;
				cout << "Password: ";
				cin.ignore();
				getline(cin, input_pass);
				cout << endl;

				string input_data = input_username + ":" + input_pass + ":";
				size_t found = file_data.find(input_data);

				if (found != string::npos) {
					string input_data = input_username + ":" + input_pass + ":";
					size_t found_start = file_data.find(input_data);

					size_t first_colon = file_data.find(':', found_start);
					size_t second_colon = file_data.find(':', first_colon + 1);
					string input_block, input_constr;
					input_block = file_data[second_colon + 1];
					input_constr = file_data[second_colon + 3];

					if (input_block == "1") {
						cout << "This account is blocked! Contact the administrator to resolve this issue" << endl << endl;
						return 'g';
					}

					set_user(input_username, input_pass, input_block, input_constr);

					if (input_username == "admin")
						return 'a';
					else
						return 'u';
				}
				else
					cout << "Incorrect login or password. " << 2 - i << " attempts left" << endl << endl;
			}
			return 'e';
		}
	}
	void about() {
		cout << "Developer: Sharuev Oleksandr Yuriyovich \nGroup: FB-81\nVariant: 19\nTask: to check the presence of lowercase and uppercase Latin letters, numbers and Cyrillic characters" << endl;
	}
	void help() {
		cout << "---------Available Commands---------" << endl;
		cout << "Guest tier:" << endl;
		cout << "\t*login" << endl;
		cout << "\t*about" << endl;
		cout << "\t*help" << endl;
		cout << "\t*exit" << endl;
		cout << "User tier:" << endl;
		cout << "\t*change_pass" << endl;
		cout << "Admin tier:" << endl;
		cout << "\t*user_list" << endl;
		cout << "\t*user_add" << endl;
		cout << "\t*user_block" << endl;
		cout << "\t*user_constr" << endl;
		cout << "------------------------------------" << endl << endl;
	}
	friend string file_to_string();
	friend void string_to_file(string);
};

class User : public Guest {
public:
	char menu() {
		string choise;
		User user;

		cout << "You have a \"User tier\"" << endl;
		cout << "Enter \"help\" to get a list of commands " << endl << endl;

		if (constr == "1" && user_pass_check(pass) == false)
			user.change_pass();

		while (1) {
			cout << "user@user:~$ ";
			cin >> choise;
			if (choise == "login")
				return user.login();
			else if (choise == "about")
				user.about();
			else if (choise == "help")
				user.help();
			else if (choise == "exit")
				return 'e';
			else if (choise == "change_pass")
				user.change_pass();
			else
				cout << "Command not found! Pleace, try again" << endl;
		}
	}
protected:
	void change_pass() {
		string file_data = file_to_string();
		string input_username, input_pass;

		if (constr == "1" && user_pass_check(pass) == false)
			cout << "Your password does not match the constraints!\nIt must contain at least: 1 Cyrillic letter, 1 lowercase Latin letter, 1 uppercase Latin letter and 1 number" << endl << endl;
		else {
			cout << "You must confirm your login data to change password! (enter \"exit\" to quit)" << endl;
			cout << "Login: ";
			cin >> input_username;
			cout << "Password: ";
			cin.ignore();
			getline(cin, input_pass);
			if (input_username == "exit" || input_pass == "exit")
				return;

			if (input_username != username || input_pass != pass) {
				cout << "Incorrect login or password!" << endl << endl;
				return;
			}
		}

		string input_data = username + ":" + pass + ":";
		size_t found_start = file_data.find(input_data);

		if (found_start != string::npos) {
			string colon = ":";
			string user_data = username + colon + pass + colon + block + colon + constr + '\n';
			size_t found_end = found_start + user_data.length();

			string string_start;
			string_start.resize(found_start);
			for (size_t i = 0; i < found_start; i++) {
				string_start[i] = file_data[i];
			}

			string string_end;
			string_end.resize(file_data.length() - found_end);
			for (int i = 0, j = found_end; file_data[j] != '\0'; i++, j++) {
				string_end[i] = file_data[j];
			}

			string new_pass, confirm_new_pass, new_file;
			while (1) {
				cout << "Enter new password (enter \"exit\" to quit): ";
				getline(cin, new_pass);
				cout << "Confirm new password (enter \"exit\" to quit): ";
				getline(cin, confirm_new_pass);
				if (new_pass == "exit" || confirm_new_pass == "exit")
					return;
				if (new_pass != confirm_new_pass) {
					cout << "Paswords don't match. Try again!" << endl << endl;
					continue;
				}
				if (constr == "1" && !user_pass_check(new_pass))
					cout << "\nYour password does not match the constraints. Try again!" << endl << endl;
				else
					break;
			}

			string new_data = username + colon + new_pass + colon + block + colon + constr + '\n';
			new_file = string_start + new_data + string_end;
			set_user(username, new_pass, block, constr);

			string_to_file(new_file);
			cout << "Success!" << endl;
		}
		else
			cout << "String not found!" << endl << endl;
	}
	friend bool user_pass_check(string pass_to_check);
};

class Admin : public User {
public:
	char menu() {
		string choise;
		Admin admin;

		cout << "You have an \"Admin tier\"" << endl;
		cout << "Enter \"help\" to get a list of commands " << endl << endl;

		while (1) {
			cout << "admin@admin:~$ ";
			cin >> choise;
			if (choise == "login")
				return admin.login();
			else if (choise == "about")
				admin.about();
			else if (choise == "help")
				admin.help();
			else if (choise == "exit")
				return 'e';
			else if (choise == "change_pass")
				admin.change_pass();
			else if (choise == "user_list")
				admin.user_list();
			else if (choise == "user_add")
				admin.user_add();
			else if (choise == "user_block")
				admin.user_block();
			else if (choise == "user_constr")
				admin.user_pass_constr();
			else
				cout << "Command not found! Pleace, try again" << endl;
		}
	}
protected:
	void user_list() {
		string file_data = file_to_string();
		cout << file_data;
	}
	void user_add() {
		string file_data = file_to_string();
		string input_username;

		cout << "Enter the username of the new user: ";
		cin >> input_username;

		string input_data = "\n" + input_username + ":";
		size_t found_start = file_data.find(input_data);

		if (found_start != string::npos) {
			cout << "User with this name already exists!" << endl << endl;
			return;
		}

		string new_user_data = input_username + "::0:0\n";
		string new_file = file_data + new_user_data;

		string_to_file(new_file);
		cout << "Success!" << endl;
	}
	void user_block() {
		string file_data = file_to_string();
		string input_username;

		cout << "Enter the username you want to block: ";
		cin >> input_username;

		string input_data = "\n" + input_username + ":";
		size_t found_start = file_data.find(input_data);

		if (found_start != string::npos) {
			size_t first_colon = file_data.find(':', found_start);
			size_t second_colon = file_data.find(':', first_colon + 1);

			file_data[second_colon + 1] = '1';
			string_to_file(file_data);

			set_user(username, pass, "1", constr);
			cout << "Success!" << endl;
		}
		else
			cout << "String not found!" << endl;
	}
	void user_pass_constr() {
		string file_data = file_to_string();
		string input_username;

		cout << "Enter the username for which you want to set password constraint: ";
		cin >> input_username;

		string input_data = "\n" + input_username + ":";
		size_t found_start = file_data.find(input_data);

		if (found_start != string::npos) {
			size_t first_colon = file_data.find(':', found_start);
			size_t second_colon = file_data.find(':', first_colon + 1);

			file_data[second_colon + 3] = '1';
			string_to_file(file_data);

			set_user(username, pass, block, "1");
			cout << "Success!" << endl;
		}
		else
			cout << "String not found!" << endl;
	}
};

string Guest::username = "";
string Guest::pass = "";
string Guest::block = "0";
string Guest::constr = "0";

string file_to_string() {
	ifstream in("users.txt", ios::binary);
	if (!in.is_open()) {
		cout << "File Open Error!" << endl;
	}
	char file_data_char[1000] = {};
	in.read(file_data_char, 1000);
	in.close();
	string file_data = string(file_data_char);
	return file_data;
}

void string_to_file(string new_file) {
	ofstream out("users.txt", ios::binary);
	if (!out.is_open()) {
		cout << "File Open Error!";
	}
	out << new_file;
	out.close();
}

bool user_pass_check(string pass_to_check) {
	if (pass_to_check == "")
		return false;
	else {
		bool is_lower = false, is_upper = false, is_digit = false, is_cyrillic = false;
		string сyrillic = "јаЅб¬в√гƒд≈е®Є∆ж«з»и…й кЋлћмЌнќоѕп–р—с“т”у‘ф’х÷ц„чЎшўщЏъџы№ьЁэёюя€•і™Ї≤≥ѓњ";

		for (size_t i = 0; i < pass_to_check.length(); i++) {
			if (сyrillic.find(pass_to_check[i]) != string::npos)
				is_cyrillic = true;
			else if (isdigit(pass_to_check[i]))
				is_digit = true;
			else if (islower(pass_to_check[i]))
				is_lower = true;
			else if (isupper(pass_to_check[i]))
				is_upper = true;
		}
		return is_lower && is_upper && is_digit && is_cyrillic;
	}
}

string data_collection() {
	string data[9] = {};
	char buffer[50];
	DWORD size;
	size = sizeof(buffer);
	GetUserName(buffer, &size);
	data[0] = string(buffer);

	GetComputerName(buffer, &size);
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
	return collected_data;
}

bool hash_check(string collected_data) {
// ’еширование
	cout << "Hashing system data..." << endl;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;

	// ѕолучение контекста криптопровайдера
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL))
		cout << "CryptAcquireContext Error" << endl;
	else
		cout << "Cryptographic provider initialized" << endl;

	// Cоздание хеш-объекта
	if (!CryptCreateHash(hProv, CALG_MD5, NULL, NULL, &hHash))
		cout << "CryptCreateHash Error" << endl;
	else
		cout << "Hash created" << endl;

	// ѕередача хешируемых данных хэш-объекту.
	DWORD data_size = collected_data.length() * sizeof(char);
	if (!CryptHashData(hHash, (BYTE*)collected_data.c_str(), data_size, NULL))
		cout << "CryptHashData Error" << endl;
	else
		cout << "Hash data loaded" << endl;

	// ѕолучание значени€ хеша
	DWORD pdwDataLen = 0;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &pdwDataLen, 0))
		cout << "Error while get hash value size" << endl;
	else
		cout << "Hash value size retrieved successful" << endl;

	BYTE* hash_value = (BYTE*)malloc(pdwDataLen);
	if (!CryptGetHashParam(hHash, HP_HASHVAL, hash_value, &pdwDataLen, 0))
		cout << "Error while get hash value" << endl;
	else
		cout << "Hash value retrieved successful" << endl;

// „тение значени€ с реестра
	HKEY hKey;

	if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Sharuev", NULL, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
		cout << "Open registry key error" << endl;
	else
		cout << "Software\\Sharuev is opened" << endl;

	DWORD lpcbSignData = 0;

	if (RegQueryValueEx(hKey, "Signature", NULL, NULL, NULL, &lpcbSignData) != ERROR_SUCCESS)
		cout << "Error computing buffer length" << endl;
	else
		cout << "Size of the buffer determined" << endl;

	LPBYTE lpSignData = (BYTE*)malloc(lpcbSignData);

	if(RegQueryValueEx(hKey, "Signature", NULL, NULL, lpSignData, &lpcbSignData) != ERROR_SUCCESS)
		cout << "Error reading registry key" << endl;
	else
		cout << "Registry key received" << endl;

// —равнение полученных данных
	if (lpcbSignData == pdwDataLen) {
		bool check = true;

		for (DWORD i = 0; i < lpcbSignData; i++) {
			if (hash_value[i] != lpSignData[i])
				check = false;
		}
		cout << endl;
		return check;
	}

	return false;
}


int main() {
	string data = data_collection();
	if (!hash_check(data)) {
		cout << "Check failed! Closing the program..." << endl;
		system("pause");
		return -1;
	}
	else {
		cout << "Welcome to my Program!" << endl << endl;
		//–асшифровка файла
		HCRYPTPROV hProv;
		HCRYPTKEY hSessionKey;
		HCRYPTHASH hHash;

		string file_pass;
		cout << "Enter file password: ";
		cin >> file_pass;
		DWORD pass_len;
		pass_len = file_pass.length();

		// ѕолучение контекста криптопровайдера
		if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, NULL))
			cout << "CryptAcquireContext Error" << endl;
		else
			cout << "Cryptographic provider initialized" << endl;

		// Cоздание хеш-объекта
		if (!CryptCreateHash(hProv, CALG_MD2, NULL, NULL, &hHash))
			cout << "CryptCreateHash Error" << endl;
		else
			cout << "Hash created" << endl;

		// ѕередача парол€ хэш-объекту
		if (!CryptHashData(hHash, (BYTE*)file_pass.c_str(), pass_len, NULL))
			cout << "CryptHashData Error" << endl;
		else
			cout << "Hash data loaded" << endl;

		// —оздание сессионного ключа, основанного на хэше, полученного из парол€.
		if (!CryptDeriveKey(hProv, CALG_RC2, hHash, 0, &hSessionKey))
			cout << "Error during CryptDeriveKey" << endl;
		else
			cout << "The key has been derived" << endl;

		// ”становка режима электронной кодовой книги
		DWORD mode = CRYPT_MODE_ECB;
		if (!CryptSetKeyParam(hSessionKey, KP_MODE, (BYTE*)&mode, 0))
			cout << "Error during set key parameters" << endl;
		else
			cout << "Key parameters successfuly set" << endl;

		// ѕолучение размера блока
		DWORD block_len;
		DWORD block_len_size;
		if (!CryptGetKeyParam(hSessionKey, KP_BLOCKLEN, (BYTE*)&block_len, &block_len_size, 0))
			cout << "Error during computing block length" << endl;
		else
			cout << "Block length successfuly computed: " << block_len << " bytes" << endl << endl;

		// ”становка размера буфера (количество байт, шифруемых за раз)
		DWORD buffer_len = block_len * 2;
		PBYTE pbBuffer = (BYTE*)malloc(buffer_len);

		bool fEOF;

		// „тение файла
		ifstream in_en("encrypted.txt", ios::binary);
		if (!in_en.is_open()) {
			ofstream out_dec("users.txt", ios::binary);
			out_dec << "<username:pass:block:constr>\nadmin::0:0" << endl;
			out_dec.close();
			cout << "The first login is recorded!\nYou can login into the system as \"admin\" with an empty password " << endl << endl;
		}
		else {
			HANDLE hSourceFileEnc = CreateFile("encrypted.txt", FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			HANDLE hDestinationFileDec = CreateFile("users.txt", FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			
			DWORD dwCountEnc;
			fEOF = FALSE;
			// –асшифровка файла encrypted
			do {
				if (!ReadFile(hSourceFileEnc, pbBuffer, block_len, &dwCountEnc, NULL))
					cout << "File read failed" << endl;
				else
					cout << "File successfuly read" << endl << endl;

				if (dwCountEnc < block_len)
					fEOF = TRUE;

				if (!CryptDecrypt(hSessionKey, 0, fEOF, 0, pbBuffer, &dwCountEnc)) {
					cout << "Wrong password!" << endl;
					system("pause");
					return -2;
				}
				else
					cout << "File successfuly decrypted" << endl << endl;

				// «апись во временный файл
				if (!WriteFile(hDestinationFileDec, pbBuffer, dwCountEnc, &dwCountEnc, NULL))
					cout << "File write failed" << endl;
				else
					cout << "Successfuly writed to file" << endl;

				// «акрытие файлов 
				if (hSourceFileEnc)
					CloseHandle(hSourceFileEnc);
				if (hDestinationFileDec)
					CloseHandle(hDestinationFileDec);
			}
			while (!fEOF);
		}
	
		// ќсновна€ программа
		setlocale(LC_ALL, "ru");

		Guest guest;
		User user;
		Admin admin;

		char choice = 'g';
		while (1) {
			switch (choice) {
			case('g'):
				choice = guest.menu();
				break;
			case('u'):
				choice = user.menu();
				break;
			case('a'):
				choice = admin.menu();
				break;
			}
			if (choice == 'e')
				break;
		}
		
	// Ўифрование новых данных
		HANDLE hSourceFileDec = CreateFile("users.txt", FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		HANDLE hDestinationFileEnc = CreateFile("encrypted.txt", FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		// Ўифрование
		DWORD dwCountDec;
		fEOF = FALSE;
		do {
			if (!ReadFile(hSourceFileDec, pbBuffer, block_len, &dwCountDec, NULL))
				cout << "File read failed" << endl;
			else
				cout << "File successfuly read" << endl << endl;

			if (dwCountDec < block_len)
				fEOF = TRUE;

			if (!CryptEncrypt(hSessionKey, 0, fEOF, 0, pbBuffer, &dwCountDec, buffer_len)) {
				cout << "File decryption failed" << endl;
				system("pause");
				return -2;
			}
			else
				cout << "File successfuly decrypted" << endl << endl;

			// «апись в шифртекста в файл encrypted
			if (!WriteFile(hDestinationFileEnc, pbBuffer, dwCountDec, &dwCountDec, NULL))
				cout << "File write failed" << endl;
			else
				cout << "Successfuly writed to file" << endl;

			// «акрытие файлов
			if (hSourceFileDec)
				CloseHandle(hSourceFileDec);
			if (hDestinationFileEnc)
				CloseHandle(hDestinationFileEnc);
		} while (!fEOF);

	// ”даление временного файла
		remove("users.txt");

	// ”ничтожение
		CryptDestroyHash(hHash);
		CryptDestroyKey(hSessionKey);
		CryptReleaseContext(hProv, NULL);

		return 0;
	}
}