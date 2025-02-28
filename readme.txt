生成短网址
curl -X POST -d "url=https://ee.zjlchb.com/?url=tcp://ee.zjlchb.com:{STUN_Et1_PORT}&custom_code=abc123&token=wXHsGFSoKoibmrpM2C4FqwGia2IYwxPerI4fzSRLPlA=" http://localhost:8080/api/generate

查询短网址
curl -X GET "http://localhost:8080/api/query?short_code=e&token=wXHsGFSoKoibmrpM2C4FqwGia2IYwxPerI4fzSRLPlA="

更新短网址
curl -X POST -d "short_code=abc123&new_url=https://ee.zjlchb.com/?url=tcp://ee.zjlchb.com:{STUN_Et1_PORT}&token=wXHsGFSoKoibmrpM2C4FqwGia2IYwxPerI4fzSRLPlA=" http://localhost:8080/api/update

删除短网址
curl -X POST -d "short_code=abc123&token=wXHsGFSoKoibmrpM2C4FqwGia2IYwxPerI4fzSRLPlA=" http://localhost:8080/api/delete