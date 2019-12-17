#ifndef HASH_CALC
#define HASH_CALC

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 *@beief 哈希值计算
 */
class HashCalc
{
public:
	
  	/*
   	 *@brief 构造函数
   	 */
	HashCalc()
	{
		iHashTableSize = 0;
		memset(xorr, 0, 12);
		memset(perm, 0, 12);
	}  
	
	void Getrnd();
	
	int Init(uint64_t iSize);
	
	uint32_t CalcHashValue(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport);
	
    static uint32_t Hash(const char *str);
	  
private:
	
	/*
	 *@beief 哈希表大小
	 */
	uint64_t iHashTableSize;
	
	uint8_t xorr[12];
	
	uint8_t perm[12];
};

#endif  //HASH_CALC