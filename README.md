# pcap-test
Forked: https://gitlab.com/gilgil/pcap-test

과제 수행용 리포지토리입니다.

# todo
* printf()를 사용할 때에는 제대로 된 자료형을 출력하도록 하기.
* 동적 할당 전, 할당할 필요가 있는지 확인 후에 할당.
* deep-copy vs shallow-copy


# Summary
* [C 구조체 패딩 크기 강제 조정하는 법](https://www.geeksforgeeks.org/how-to-avoid-structure-padding-in-c/)
```C
#pragma pack(1)                 // 강제 조정. 
struct my_struct{
	uint8_t _uint8 u8;
	uint16_t _uint16 u16;
	uint32_t _uint32 u32;
};
```

* 비트 단위 자료형 
```C
u_char BIT_1:1;
u_char BIT_2:2;
u_char BIT_3:3;
u_char BIT_4:4;
```

* 전처리 조건문 
```C
struct my_struct{
#if BYTE_ORDER == LITTLE_ENDIAN // BYTE_ORDER에 따라 조정.
	u_char IHL:4;
	u_char VER:4;
#else
	u_char VER:4;
	u_char IHL:4;
#endif
};
```

* static
```C
int func(){
	static char buff[256];	// func() 내부에서만 접근 가능한 전역변수. (정적변수)
	return 0;
}
```

* [__thread](https://stackoverflow.com/questions/32245103/how-does-the-gcc-thread-work)
```C
int func(){
	static __thread char buff[256]; // thread-safe 정적변수
	return 0;
}
};
```

* [inet_ntop(3)](https://man7.org/linux/man-pages/man3/inet_ntop.3.html)
```C
const char *inet_ntop(
	int af,
	const void *restrict src,
	char *restrict dst,
	socklen_t size
);

int main(){
	// inet_ntoa는 내부에서 static을 사용함.
	char* src_ip = inet_ntoa(ip->src);
	char* dst_ip = inet_ntoa(ip->dst);	// static 사용하므로, char* src_ip가 가리키는 주소가 덮어씌워짐.
	printf("src_ip = %s\n", src_ip);	// dst_ip 출력
	printf("dst_ip = %s\n", dst_ip);	// dst_ip 출력

	// 예방법: inet_ntop 사용 or 바로 소비.
	char* src_ip = inet_ntop(ip->src);
	char* dst_ip = inet_ntop(ip->dst);
	printf("src_ip = %s\n", src_ip);	// src_ip 출력
	printf("dst_ip = %s\n", dst_ip);	// dst_ip 출력
}
```
