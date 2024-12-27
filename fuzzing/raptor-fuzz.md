The bug report below was sent to the Debian bug tracker on 2024-03-28 and logged as [bug #1067896](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1067896).
No CVE has been attributed as of 2024-07-27.

===

Hi,

Following on Hanno Bock's footsteps [1], I decided to fuzz libraptor2 [2][3] and after a few days found a couple of issues.

The memcpy integer underflow issue is probably exploitable, although in all honesty I didn't spend much time analysing whether that is possible or not. The heap read overflow is probably not exploitable, but again, very little time was spent analysing this, as I was just playing around with my custom fuzzer.

I tried contacting the author, the Debian and the Ubuntu security teams, and while the author acknowledged the issue, it was never resolved or looked into. Therefore I am now making it public to see if this can be fixed.

The issues below are still present in the latest git tag 72a8a2dcdd56527dfe9f23b273d9521a11811ef3 [4], committed Dec 4 2023.

Report follows below, please let me know if you need more info.

Regards,
Pedro Ribeiro (pedrib@gmail.com) from Agile Information Security

[1] https://www.openwall.com/lists/oss-security/2020/11/13/1  
[2] https://tracker.debian.org/pkg/raptor2  
[3] https://github.com/dajobe/raptor  
[4] https://github.com/dajobe/raptor/commit/72a8a2dcdd56527dfe9f23b273d9521a11811ef3  


## 1. Integer Underflow in `raptor_uri_normalize_path()`

There's an integer underflow in a path length calculation in `raptor_uri_normalize_path()`.

This can be triggered by running the PoC below:

```
utils/rapper -i turtle memcpy_int_underflow.poc
rapper: Parsing URI file:///memcpy_int_underflow.poc with parser turtle
rapper: Serializing with serializer ntriples
free(): invalid pointer
Aborted
```

With an ASAN build of `rapper` we can more clearly see the issue without the need of a debugger:

```
raptor-asan/utils/rapper -i turtle memcpy_int_underflow.poc
rapper: Parsing URI file:///memcpy_int_underflow.poc with parser turtle
rapper: Serializing with serializer ntriples
=================================================================
==2406522==ERROR: AddressSanitizer: negative-size-param: (size=-5)
    #0 0x5f90a3e1cf33 in __interceptor_memcpy (/raptor/raptor-asan/utils/.libs/rapper+0x3cf33) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)
    #1 0x7c902fa96e5a in raptor_uri_resolve_uri_reference (/raptor/raptor/src/.libs/libraptor2.so.0+0x19e5a) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #2 0x7c902fa9741c in raptor_new_uri_relative_to_base_counted (/raptor/raptor/src/.libs/libraptor2.so.0+0x1a41c) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #3 0x7c902fa9747a in raptor_new_uri_relative_to_base (/raptor/raptor/src/.libs/libraptor2.so.0+0x1a47a) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #4 0x7c902fab93fc in turtle_lexer_lex (/raptor/raptor/src/.libs/libraptor2.so.0+0x3c3fc) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #5 0x7c902fabc3ec in turtle_parser_parse (/raptor/raptor/src/.libs/libraptor2.so.0+0x3f3ec) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #6 0x7c902fabebb9 in turtle_parse turtle_parser.c
    #7 0x7c902fabf3ff in raptor_turtle_parse_chunk turtle_parser.c
    #8 0x7c902fa92de4 in raptor_parser_parse_chunk (/raptor/raptor/src/.libs/libraptor2.so.0+0x15de4) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #9 0x7c902fa92fc1 in raptor_parser_parse_file_stream (/raptor/raptor/src/.libs/libraptor2.so.0+0x15fc1) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #10 0x7c902fa93174 in raptor_parser_parse_file (/raptor/raptor/src/.libs/libraptor2.so.0+0x16174) (BuildId: 9edf75a105deaf007b9332b0a0367c8ad4af744d)
    #11 0x5f90a3ed9492 in main (/raptor/raptor-asan/utils/.libs/rapper+0xf9492) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)
    #12 0x7c902f7816c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #13 0x7c902f781784 in __libc_start_main csu/../csu/libc-start.c:360:3
    #14 0x5f90a3e01650 in _start (/raptor/raptor-asan/utils/.libs/rapper+0x21650) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)

(...)

SUMMARY: AddressSanitizer: negative-size-param (/raptor/raptor-asan/utils/.libs/rapper+0x3cf33) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be) in __interceptor_memcpy
==2406522==ABORTING
```

The crash occurs because `raptor_uri_normalize_path()`, which does some complicated jiggling to normalize paths, and fails to take into account integer underflows. The function will not be shown here as it is quite complex. 

`raptor_uri_normalize_path()` is called from `raptor_uri_resolve_uri_reference()` to normalize a path, and the crash occurs in a juicy `memcpy()` inside  `raptor_uri_resolve_uri_reference()` (`raptor_rfc2396.c:664`) where `result.path_len` is the underflowed integer (ASAN's `negative-size-param`), and `result.path` is attacker controlled:

```c
  if(result.path) {
    memcpy(p, result.path, result.path_len);
    p+= result.path_len;
  }
```

The non-ASAN crash in `free()` shown at the top occurs in line 685:

```c
  if(path_buffer)
    RAPTOR_FREE(char*, path_buffer);
```

The fix, however, is rather simple! The function contains several of these checks after each calculation:

```c
#if defined(RAPTOR_DEBUG)
  if(path_len != strlen((const char*)path_buffer))
    RAPTOR_FATAL3("Path length %ld does not match calculated %ld.", (long)strlen((const char*)path_buffer), (long)path_len);
#endif
```

If we remove the `#if defined` / `#endif` around this code in lines 396 and 399, we get an error instead of a crash:
`raptor_rfc2396.c:397:raptor_uri_normalize_path: fatal error: Path length 0 does not match calculated -5.Aborted`


### 1.1 Steps to reproduce

`rapper -i turtle memcpy_int_underflow.poc`

Contents of `memcpy_int_underflow.poc`:

```
@base <http:o/www.w3.org/2001/sw/DataA#cess/df1.ttl> .
@prefix bdf: <.&/../?D/../../1999/02/22-rdf-syntax-ns#>/dbpe
```

### 1.2 Patch

```diff
diff --git a/src/raptor_rfc2396.c b/src/raptor_rfc2396.c
index 89183d96..f58710c5 100644
--- a/src/raptor_rfc2396.c
+++ b/src/raptor_rfc2396.c
@@ -393,10 +393,8 @@ raptor_uri_normalize_path(unsigned char* path_buffer, size_t path_len)
   }


-#if defined(RAPTOR_DEBUG)
   if(path_len != strlen((const char*)path_buffer))
     RAPTOR_FATAL3("Path length %ld does not match calculated %ld.", (long)strlen((const char*)path_buffer), (long)path_len);
-#endif

   /* RFC3986 Appendix C.2 / 5.4.2 Abnormal Examples
    * Remove leading /../ and /./
```

## 2. Heap read buffer overflow in `raptor_ntriples_parse_term_internal()`

Didn't have any time to analyse this :-(, here's the full ASAN output:

```
raptor-asan/utils/rapper -i nquads heap_read_overflow.poc
rapper: Parsing URI file:///heap_read_overflow.poc with parser nquads
rapper: Serializing with serializer ntriples
=================================================================
==2449874==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000004d6f at pc 0x70f0eec00a68 bp 0x7ffecb914e50 sp 0x7ffecb914e48
READ of size 1 at 0x602000004d6f thread T0
    #0 0x70f0eec00a67 in raptor_ntriples_parse_term_internal raptor_ntriples.c
    #1 0x70f0eebfffc8 in raptor_ntriples_parse_term (/raptor-asan/src/.libs/libraptor2.so.0+0x8cfc8) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #2 0x70f0eec37fa1 in raptor_ntriples_parse_line ntriples_parse.c
    #3 0x70f0eec36782 in raptor_ntriples_parse_chunk ntriples_parse.c
    #4 0x70f0eeba9486 in raptor_parser_parse_chunk (/raptor-asan/src/.libs/libraptor2.so.0+0x36486) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #5 0x70f0eeba96b6 in raptor_parser_parse_file_stream (/raptor-asan/src/.libs/libraptor2.so.0+0x366b6) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #6 0x70f0eeba9aac in raptor_parser_parse_file (/raptor-asan/src/.libs/libraptor2.so.0+0x36aac) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #7 0x5f25d7d8e492 in main (/raptor-asan/utils/.libs/rapper+0xf9492) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)
    #8 0x70f0ee8776c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #9 0x70f0ee877784 in __libc_start_main csu/../csu/libc-start.c:360:3
    #10 0x5f25d7cb6650 in _start (/raptor-asan/utils/.libs/rapper+0x21650) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)

0x602000004d6f is located 1 bytes before 16-byte region [0x602000004d70,0x602000004d80)
allocated by thread T0 here:
    #0 0x5f25d7d5047e in malloc (/raptor-asan/utils/.libs/rapper+0xbb47e) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)
    #1 0x70f0eec35c4b in raptor_ntriples_parse_chunk ntriples_parse.c
    #2 0x70f0eeba9486 in raptor_parser_parse_chunk (/raptor-asan/src/.libs/libraptor2.so.0+0x36486) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #3 0x70f0eeba96b6 in raptor_parser_parse_file_stream (/raptor-asan/src/.libs/libraptor2.so.0+0x366b6) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #4 0x70f0eeba9aac in raptor_parser_parse_file (/raptor-asan/src/.libs/libraptor2.so.0+0x36aac) (BuildId: 2591e3251613881bd804fabbc6c02dd6e7b7b76e)
    #5 0x5f25d7d8e492 in main (/raptor-asan/utils/.libs/rapper+0xf9492) (BuildId: 31b11a035fdbbfb23ddb7c1a5db60302956622be)
    #6 0x70f0ee8776c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: heap-buffer-overflow raptor_ntriples.c in raptor_ntriples_parse_term_internal
Shadow bytes around the buggy address:
  0x602000004a80: fa fa fd fd fa fa fd fd fa fa fd fd fa fa fd fd
  0x602000004b00: fa fa fd fd fa fa fd fd fa fa fd fd fa fa 00 00
  0x602000004b80: fa fa 00 00 fa fa 00 00 fa fa 00 00 fa fa 00 fa
  0x602000004c00: fa fa 00 00 fa fa 00 fa fa fa 06 fa fa fa 00 01
  0x602000004c80: fa fa 00 01 fa fa 07 fa fa fa 00 03 fa fa 06 fa
=>0x602000004d00: fa fa 00 01 fa fa 05 fa fa fa 04 fa fa[fa]00 00
  0x602000004d80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000004e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000004e80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000004f00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x602000004f80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==2449874==ABORTING
```

### 2.1 Steps to reproduce

`rapper -i nquads heap_read_overflow.poc`

Contents of `heap_read_overflow.poc`:

```
_:/exaple/o
```
