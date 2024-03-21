#include <iostream>
#include <iomanip>

#include "filters.h"
#include "rdrand.h"
#include "hex.h"

using namespace std;
using namespace CryptoPP;

// To use intrinsics if available, then compile/link with:
//   g++ -g3 -O1 -Wall -march=native rdrand.cxx ./libcryptopp.a -o rdrand.exe
// Or:
//   g++ -g3 -O1 -Wall -mrdrnd rdrand.cxx ./libcryptopp.a -o rdrand.exe

// To use ASM if the compiler supports it, then compile/link with:
//   g++ -g3 -O1 -Wall rdrand.cxx ./libcryptopp.a -o rdrand.exe

int main()
{
	RDRAND prng;
	
	if (prng.Available())
		cout << "RDRAND is available" << endl;
	else
		cout << "RDRAND is not available" << endl;
	
	try
	{
		for (unsigned int i=1; i<=256; i++)
		{
			string vals;
			vals.reserve(i);
	
			RandomNumberSource rns(prng, i, true, new HexEncoder(new StringSink(vals)));
			cout << vals << endl;
		}
	}
	catch(const Exception& ex)
	{
		cerr << ex.what() << endl;
		return 1;
	}
	
	return 0;
}
