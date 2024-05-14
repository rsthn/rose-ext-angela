# Angela Encryption Extension


### (`eax:encrypt` \<key> \<plain-text>)
Encrypts the specified buffer using Angela.
```lisp
(eax:encrypt 'hello_world' 'my_plain_text')
; (bytes)
```

### (`eax:decrypt` \<key> \<cipher-text>)
Decrypts the specified cipher using Angela.
```lisp
(eax:decrypt 'hello_world' (eax:encrypt 'hello_world' 'my_plain_text'))
; my_plain_text
```
