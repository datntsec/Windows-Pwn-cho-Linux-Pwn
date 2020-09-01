Windows-Pwn-cho-Linux-Pwn
-

Mới bắt đầu exploit trên windows, mình thấy khá khó, tìm kiếm các bài Pwn về windows thì khá ít, và không có mấy tài liệu hướng dẫn. Tình cờ mình biết được 1 bài được viết bằng tiếng Trung nói về cách Pwn trên Windows cho người rành về Pwn trên Linux, nên giờ mình dựa vào đó và viết lại bằng tiếng Việt cho các bạn dễ hiểu.


# Đối tượng:
Bài viết dành cho những ai đã biết về các kĩ thuật Pwn trên Linux nhưng hoàn toàn không biết gì về Pwn trên Windows. 
# Kiến thức có được trong bài viết:
+ Biết cách build một Pwn test trên môi trường Windows (các công cụ gồm socat, pwntools, IDA).
+ Nguyên tắc hoạt động của tiến trình Windows user mode và một số công cụ để luyện tập.
+ Phương thức cơ bản của Windows heap management.

## File luyện tập: [`sctf_EasyWinHeap.zip`](sctf_EasyWinHeap.zip)
## Hệ điều hành: `Windows 7 sp1`
# Thiết lập môi trường:
+ Khác với winpwn: pwntools dành cho Windows (mini), chúng ta vẫn sẽ sử dụng pwntools để giải quyết [`EasyWinHeap`](sctf_EasyWinHeap.zip), mặc dù pwntools không sử dụng trực tiếp trên Windows được, chúng ta sẽ sử dụng socat để remote.
  + [`Socat for windows`](https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/)
  + [`socat 1.7.3.2 for Windows`](https://www.cybercircuits.co.nz/web/blog/socat-1-7-3-2-for-windows)
  + Hướng dẫn sử dụng socat trên Windows: [`Link 1`](https://github.com/datntsec/H-ng-d-n-s-d-ng-socat-tr-n-windows) or [`Link 2`](https://juejin.im/post/6844903954438963207)
  Để cho tiện thì mình sẽ [`thiết lập biến môi trường cho socat`](https://github.com/datntsec/H-ng-d-n-s-d-ng-socat-tr-n-windows#2-thi%E1%BA%BFt-l%E1%BA%ADp-enviroment), sau này dùng thì chỉ việc gọi lệnh socat trong cmd là dùng được, khỏi phải dẫn đường dẫn trực tiếp, ví dụ như lệnh sau ta sẽ chạy file `EasyWinHeap.exe` với `socat`:
  ``` bash 
  socat tcp-listen:8888,fork EXEC:EasyWinHeap.exe,pipes &
  ```
  Sau khi chạy socat thành công, khi có một kết nối đến, nó sẽ chạy chương trình EasyWinHeap.exe trên một tiến trình mới, ta chỉ việc đính kèm tiền trình này vào `IDA` (Pro) để tiến hành `debugging`. Ngoài ra, nếu bạn sử dụng pwntools script để giải, bạn có thể gọi thêm `raw_input` sau khi thực hiện remote và kết nối thành công. Việc này giúp cho đoạn script sẽ không tiếp tục gửi data, còn socat thì đã bắt đầu tiến trình nhưng IDA sẽ không bỏ lỡ breakpoint khi đính kèm tiền trình và. Ví dụ:
  ``` python
  from pwn import *
  context.log_level = 'debug'
  io = remote("10.10.10.137",8888)

  sla         = lambda delim,data           :  (io.sendlineafter(delim, data))
  add         = lambda size           	  :  (sla("option >\r\n", '1'),sla("size >\r\n", str(size)))

  raw_input()
  add(1)
  io.interactive()
  ```
  



## Tham khảo: [`Getting started with SCTF 2020 EasyWinHeap Windows Pwn`](https://xuanxuanblingbling.github.io/ctf/pwn/2020/07/09/winpwn/?fbclid=IwAR1goy2nYXxkLKbq_cayyHaBtAEZSb2PsIj2ly7Km3zOjWBHQkhxR7zML5E)
