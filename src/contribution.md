# 如何贡献本项目

欢迎各位读者对[本项目 (The Huge Security Book)](https://github.com/ChenMiaoi/huge-security-books)的阅读，如果在阅读期间有任何问题，可以[点击此处](https://github.com/ChenMiaoi/huge-security-books/issues)进行上报，我会及时修复问题！

当然，本项目也欢迎各位读者的无私贡献，无论是投稿或者是支持更好的翻译或者是新增其他模块。在贡献之前，我们需要了解如何贡献本项目。

笔者的环境本地环境如下：

``` bash
OS: Fedora 42(Server Edition)
Rust: cargo 1.91.0 (ea2d97820 2025-10-10)
mdbook: mdbook v0.4.52
```

The Huge Security Book 使用了 `mdbook` 进行构建，本节主要介绍了如何在用户本地自行搭建 The Huge Security Book 进行贡献，并介绍贡献的一些规范。

本项目目前支持的发行版本有：

- Fedora 42
- Ubuntu 24.04

至于其他发行版本，目前暂未支持，如读者在构建时发现其他发行版本可用，可提交 [Pull Request](https://github.com/ChenMiaoi/huge-security-books/pulls) 对本节的支持列表做出修改。

## 安装 Rust

- 国内用户

如果国内用户打算构建本项目，**并且当前主机上没有`rust`**，那么请参考[rsproxy](https://rsproxy.cn/)进行安装。

安装成功后，请检查对应版本，本项目要求\\( rust \ version \ge 1.46 \\)

``` bash
cargo --version
cargo 1.91.0 (ea2d97820 2025-10-10)
```

- 国外用户

国外用户请直接参考[rust](https://rust-lang.org/learn/get-started/)进行安装：

``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 安装 mdbook

安装`mdbook cli`的方式有多种，本文档主要采用下方介绍的第一种方式，如有其他需要，请参考其他方式。

- 从[crate.io](https://crates.io/crates/mdbook)中直接安装

``` bash
cargo install mdbook
```

- 从[github release](https://github.com/rust-lang/mdBook/releases)上下载解压

``` bash
wget https://github.com/rust-lang/mdBook/releases/download/v0.4.52/mdbook-v0.4.52-x86_64-unknown-linux-gnu.tar.gz

tar zxvf mdbook-v0.4.52-x86_64-unknown-linux-gnu.tar.gz
```

- 从[crate.io](https://crates.io/crates/mdbook)中安装最新版本

``` bash
cargo install --git https://github.com/rust-lang/mdBook.git mdbook
```

安装完成后，可以通过运行如下命令进行检查：

``` bash
mdbook --version
mdbook v0.4.52
```

## 构建项目

完成上面的依赖安装后 (`rust`和`mdbook`)，读者可以`fork`本仓库后，进行克隆到本地 (此处直接使用了上游仓库，请读者自行更换为对应的仓库链接)：

``` bash
git clone git@github.com:ChenMiaoi/huge-security-books.git

cd huge-security-books
```

然后可以直接开始构建，或查看构建命令：

``` bash
make help
Available targets:
  build     - Build the mdBook
  run       - Build and serve the book on 0.0.0.0
  watch     - Watch & rebuild the book on changes
  check-ci  - Run tests and custom CI checks
  clean     - Clean build & cargo artifacts

Use 'make <target>' to run a specific action.
```

使用`build`命令进行构建：

``` bash
2025-11-14 03:30:55 [INFO] (mdbook::book): Book building has started
2025-11-14 03:30:55 [INFO] (mdbook::book): Running the html backend
```

> 虚拟机配置
>> 如果用户在物理机上构建，那么不需要参考这一小节。
>> 如果使用虚拟机，在有防火墙的情况下无法直接查看到 The Huge Security Book 在浏览器的页面 (默认虚拟机是 server version with no GUI)；因此需要关闭虚拟机防火墙，并将运行的监听 ip 绑定为"0.0.0.0"

``` bash
# For Fedora
sudo systemctl stop firewalld
sudo systemctl disable firewalld

# For Ubuntu
sudo systemctl stop ufw
sudo systemctl disable ufw
```

使用`run`命令启动服务：

``` bash
make run
2025-11-14 03:35:35 [INFO] (mdbook::book): Book building has started
2025-11-14 03:35:35 [INFO] (mdbook::book): Running the html backend
2025-11-14 03:35:35 [INFO] (mdbook::book): Book building has started
2025-11-14 03:35:35 [INFO] (mdbook::book): Running the html backend
2025-11-14 03:35:35 [INFO] (mdbook::cmd::serve): Serving on: http://0.0.0.0:3000
```

## 提交代码规范

假设已经做完任何更改，请使用`check-ci`命令进行检查，以便提交 Pull Request 时能够通过 CI 检查。

> 对于提交信息，**本项目统一采用 `commit_type(where): msg`** 这样的格式进行修改：
> ``` bash
> feat(src/contribution): Add how to contribute page for book
> ```
> 顺带一提，请加上您的 `Signed-off-by`: 
> ``` bash
> git commit -s
> ```

``` bash
make check-ci
number of HTML files scanned: 8
number of HTML redirects found: 0
number of links checked: 130
number of links ignored due to external: 10
number of links ignored due to exceptions: 0
number of intra doc links ignored: 0
errors found: 0
Link check completed successfully!
✅ Link checking completed successfully

🎉 All steps executed successfully. 🚀
```
