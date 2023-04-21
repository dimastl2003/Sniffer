#include <iostream>
#include <WinSock2.h>
#pragma comment(lib, "Ws2_32.lib")
#include <string>
#include <fstream>

#pragma warning(disable:4996)

#define MAX_PACKET_SIZE    0x10000
#define SIO_RCVALL		0x98000001

char Buffer[MAX_PACKET_SIZE];

// Структура IP-пакета
typedef struct _IPHeader
{
	unsigned char  ver_len;		// версия и длина заголовка
	unsigned char  tos;			// тип сервиса 
	unsigned short length;		// длина всего пакета 
	unsigned short id;			// ID
	unsigned short flgs_offset;	// флаги и смещение
	unsigned char  ttl;			// время жизни 
	unsigned char  protocol;	// протокол 
	unsigned short xsum;		// контрольная сумма 
	unsigned long  src;			// IP-адрес отправителя 
	unsigned long  dest;		// IP-адрес назначения 
	unsigned short* params;		// параметры (до 320 бит)
	unsigned char* data;		// данные (до 65535 октетов)
} IPHeader;

char src[10];
char dest[10];
char ds[15];
unsigned short lowbyte;
unsigned short hibyte;

char text[128] = "";

using namespace std;

int main(int argc, char* argv[]) {
	// Инициализация
	WSADATA wsaData;
	WORD DLLVersion = MAKEWORD(2, 1);

	if (WSAStartup(DLLVersion, &wsaData) != 0) {
		cout << "Error\n" << endl;
		return 1;
	}

	// Создаем сокет
	SOCKET sock;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	SOCKADDR_IN addr;
	IN_ADDR addr1;

	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;

	addr.sin_addr.s_addr = inet_addr(argv[1]);

	// Привязываем локальный адрес к сокету
	bind(sock, (SOCKADDR*)&addr, sizeof(SOCKADDR));

	// Promiscuous mode
	DWORD flag = TRUE;
	ioctlsocket(sock, SIO_RCVALL, &flag);

	while (true) {
		int count = recv(sock, Buffer, sizeof(Buffer), 0);

		if (count >= sizeof(IPHeader)) {
			IPHeader* hdr = (IPHeader*)Buffer;

			strcat(text, "Packet: ");

			// Преобразуем в понятный вид адрес отправителя
			strcat(text, "From: ");

			addr1.s_addr = hdr->src;
			strcat(text, inet_ntoa(addr1));
			
			// Преобразуем в понятный вид адрес получателя
			strcat(text, " To ");

			addr1.s_addr = hdr->dest;
			strcat(text, inet_ntoa(addr1));

			// Вычисляем протокол
			strcat(text, " Protocol: ");

			if (hdr->protocol == IPPROTO_TCP) strcat(text, "TCP ");
			if (hdr->protocol == IPPROTO_UDP) strcat(text, "UDP ");

			// Меняем байты местами
			strcat(text, "Size: ");

			lowbyte = hdr->length >> 8;
			hibyte = hdr->length << 8;
			hibyte = hibyte + lowbyte;

			itoa(hibyte, ds, sizeof(ds));
			strcat(text, ds);

			// Вычисляем время жизни пакета
			itoa(hdr->ttl, ds, sizeof(ds));
			strcat(text, " TTL:");
			strcat(text, ds);

			// Выводим полученную информацию в txt файл
			ofstream out(argv[2], ios::app);

			if (out.is_open()) {
				out << text << endl;
			}
			out.close();

			strcpy(text, "");
		}
	}
	closesocket(sock);
	WSACleanup();
	return 0;
}