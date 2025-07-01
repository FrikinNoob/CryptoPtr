# CryptoPtr
simple smart ptr

```cpp
	using funcPtr_t = decltype(&ReadProcessMemory);
	auto funcPtr = enc::make_unique_enc<funcPtr_t>(ReadProcessMemory);
	funcPtr_t* pptr = funcPtr.get();
	funcPtr_t ptr = *pptr;
	printf("%p, %p, %p\n", pptr, ptr, funcPtr.get_enc_value());

  000000000053CF00, 00007FFE650FC830, 1CF3A21D1DFE0099
```
