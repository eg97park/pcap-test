# pcap-test
Forked: https://gitlab.com/gilgil/pcap-test

과제 수행용 리포지토리입니다.

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
