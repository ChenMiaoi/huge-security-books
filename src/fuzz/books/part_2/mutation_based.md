# Mutation-Based Fuzzing

**大多数随机生成的输入在语法上是无效的，因此会被处理程序快速拒绝。为了测试输入处理之外的功能，我们必须提高获得有效输入的概率。其中一种方法是所谓的变异模糊测试——即对现有输入引入微小改动，这些改动可能仍保持输入的有效性，同时能触发新的程序行为。我们将展示如何创建这类变异，并如何引导它们覆盖尚未执行的代码区域，这一方法应用了流行模糊测试工具 AFL 的核心原理**。

- 预备知识
  - 学习[Fuzzing](../part_2/fuzzing_inputs.md)
  - 学习[Coverage](../part_2/code_coverage.md)

## Fuzzing with Mutations

2013 年 11 月，美国模糊测试工具 American Fuzzy Lop（简称 AFL）首个版本正式发布。自问世以来，AFL 已成为最成功的模糊测试工具之一，并衍生出多个变种版本（例如 AFLFast、AFLGo 和 AFLSmart，本书将对这些变种进行讨论）。AFL 的推广使得模糊测试成为自动化漏洞检测的主流选择——它首次证明：在众多安全关键型实际应用中，漏洞可以被大规模自动检测出来。本章将介绍变异模糊测试的基础知识；

下一节将进一步阐述如何引导模糊测试针对特定代码目标。

## Fuzzing a URL Parser

许多程序在处理输入数据前，都要求这些数据必须符合特定的格式要求。以 URL（网络地址）处理程序为例——只有当 URL 符合有效格式规范（即标准 URL 格式）时，程序才能正确解析。那么当我们使用随机输入进行模糊测试时，实际生成有效 URL 的概率有多大呢？

要深入理解这个问题，我们需要剖析 URL 的组成结构。一个完整的 URL 由多个要素构成：

``` bash
scheme://netloc/path?query#fragment
```

其中：

- scheme（协议方案）：指定要使用的通信协议，包括 http、https、ftp、file 等
- netloc（网络位置）：表示要连接的主机名称，例如 www.google.com
- path（路径）：指主机上的具体资源路径，例如 search
- query（查询参数）：包含键值对参数列表，例如 q=fuzzing
- fragment（片段标识）：用于标记所获取文档中的特定位置，例如 #result

``` bash
urlparse("http://www.google.com/search?q=fuzzing")
ParseResult(scheme='http', netloc='www.google.com', path='/search', params='', query='q=fuzzing', fragment='')
```

我们看到，结果是如何将 URL 的各个部分编码到不同属性中的。

现在，让我们假设我们有一个程序，它以一个 URL 作为输入。为了简化问题，我们不会让它做太多事情；我们只是让它检查传入的 URL 是否有效。如果 URL 是有效的，它返回 True；否则，它会抛出一个异常。

``` py
def http_program(url: str) -> bool:
    supported_schemes = ["http", "https"]
    result = urlparse(url)
    if result.scheme not in supported_schemes:
        raise ValueError("Scheme must be one of " + 
                         repr(supported_schemes))
    if result.netloc == '':
        raise ValueError("Host must be non-empty")

    # Do something with the URL
    return True
```

现在，让我们去对 http_program() 进行模糊测试（fuzz）。在进行模糊测试时，我们使用全部可打印的 ASCII 字符，这样便包括了冒号 (:)、斜杠 (/) 以及小写字母等字符。

``` bash
fuzzer(char_start=32, char_range=96)
'"N&+slk%h\x7fyp5o\'@[3(rW*M5W]tMFPU4\\P@tz%[X?uo\\1?b4T;1bDeYtHx #UJ5w}pMmPodJM,_'
```

如果我们没有任何限制的随机进行 `fuzz()` 生成测试数据，实际上生成一个有效 URL 的概率有多大呢？我们需要我们的字符串以 "http://" 或 "https://" 开头。我们先来看 "http://" 的情况。这是七个非常特定的字符，我们必须从这七个字符开始。随机生成这七个字符的概率（在 96 个不同字符的范围内）是 \\( 1:96^7 \\)，生成一个 "https://" 前缀的概率甚至更低，为 \\( 1:96^8 \\)。那么总的概率为：

\\[
  likelihood = \frac{1}{96^7} + \frac{1}{96^8} = 1.344627131107667e-14
\\]

即使我们进行大量并行化处理，我们仍然需要等待数月甚至数年的时间。而这一切仅仅是为了获得一次成功的运行，从而让测试深入到 http_program() 的内部逻辑。

基本的模糊测试能够较好地测试 urlparse() 函数。如果这个解析函数中存在错误，那么模糊测试有较大的机会将其发现。但是，只要我们无法生成一个有效的输入（比如一个格式正确的 URL），我们就无法幸运地触及到程序中更深层次的功能逻辑。

## Mutating Inputs

**另一种方法不是完全从头开始生成随机字符串，而是从一个已知的合法输入入手，然后对其进行后续的变异操作**。在这个上下文中，**“变异”指的是一种简单的字符串操作——比如插入一个（随机的）字符、删除一个字符，或者修改某个字符表示中的一个比特位。这种方式被称为变异模糊测试（mutational fuzzing），与我们前面讨论过的生成式模糊测试（generational fuzzing）技术形成对比**。

以下是一些你可以用来开始的变异操作示例：

``` py
def delete_random_character(s: str) -> str:
    """Returns s with a random character deleted"""
    if s == "":
        return s

    pos = random.randint(0, len(s) - 1)
    # print("Deleting", repr(s[pos]), "at", pos)
    return s[:pos] + s[pos + 1:]

def insert_random_character(s: str) -> str:
    """Returns s with a random character inserted"""
    pos = random.randint(0, len(s))
    random_character = chr(random.randrange(32, 127))
    # print("Inserting", repr(random_character), "at", pos)
    return s[:pos] + random_character + s[pos:]

def flip_random_character(s):
    """Returns s with a random bit flipped in a random position"""
    if s == "":
        return s

    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    # print("Flipping", bit, "in", repr(c) + ", giving", repr(new_c))
    return s[:pos] + new_c + s[pos + 1:]
```

这样，我们就可以从上述操作中，获取到一系列合法的输入。

现在的思路是：如果我们手头已经有一些合法的输入，就可以通过对这些输入应用上述某种变异操作，来生成更多的候选输入。为了理解这一过程是如何运作的，让我们回到 URL 的例子上来。

## Mutating URLs

现在，让我们回到 URL 解析的问题上来。我们来创建一个函数 is_valid_url()，用于检查 http_program() 是否接受某个输入（即判断该输入是否为一个有效的 URL）

``` py
def is_valid_url(url: str) -> bool:
    try:
        result = http_program(url)
        return True
    except ValueError:
        return False
```

现在，让我们对一个给定的 URL 应用 mutate() 函数，并观察我们能获得多少个有效的输入。我们可以发现，通过对原始输入进行变异，我们得到了很高比例的有效输入。

那么，通过变异一个以 `http:` 开头的种子输入来生成一个以 `https:` 开头的输入，其概率有多大呢？我们需要插入一个正确的字符 's'（从 96 个可打印字符中选中的概率为 \\( 1:96 \\)），并且把这个字符插入到正确的位置（概率为 \\( 1:l \\)，其中 l 是输入的长度），同时还需要选择“插入”这个变异操作（假设选择该操作的概率为 \\(1:3 \\)）。这意味着，平均而言，我们需要进行这么多次变异尝试，才能偶然生成一个包含 https:前缀的输入。

当然，如果我们想要生成一个比如 "ftp://" 这样的前缀，我们就需要进行更多的变异操作，也需要运行更多次尝试 —— 但最重要的是，我们需要应用多次变异，而不是一次简单的变异就能达到目标。

## Multiple Mutations

到目前为止，我们只是在样本字符串上应用了一次单一的变异。然而，我们也可以应用多次变异，从而对字符串进行更大幅度的改动。例如，如果我们在一个样本字符串上应用 20 次变异，会发生什么呢？


``` bash
0 mutations: 'http://www.google.com/search?q=fuzzing'
5 mutations: 'http:/L/www.googlej.com/seaRchq=fuz:ing'
10 mutations: 'http:/L/www.ggoWglej.com/seaRchqfu:in'
15 mutations: 'http:/L/wwggoWglej.com/seaR3hqf,u:in'
20 mutations: 'htt://wwggoVgle"j.som/seaR3hqf,u:in'
25 mutations: 'htt://fwggoVgle"j.som/eaRd3hqf,u^:in'
30 mutations: 'htv://>fwggoVgle"j.qom/ea0Rd3hqf,u^:i'
35 mutations: 'htv://>fwggozVle"Bj.qom/eapRd[3hqf,u^:i'
40 mutations: 'htv://>fwgeo6zTle"Bj.\'qom/eapRd[3hqf,tu^:i'
45 mutations: 'htv://>fwgeo]6zTle"BjM.\'qom/eaR[3hqf,tu^:i'
```

正如你所看到的，原始的种子输入几乎已经变得难以辨认了。通过对输入进行一次又一次的变异，我们获得了更加多样化的输入数据。

为了在单个工具或类中实现这样的多次变异，让我们引入一个名为 MutationFuzzer​ 的类。它接收一个种子（即一列字符串）作为输入，同时还可以设定变异的最小次数和最大次数。

接下来，我们将通过向 MutationFuzzer​ 类中添加更多方法来进一步扩展它的功能。在 Python 语言中，要求我们必须将一个类的所有方法定义在一个连续的代码块中，也就是说，整个类必须一次性完整地定义出来。

然而，我们更希望能够一个方法一个方法地介绍和讲解，而不是一次性把所有方法都写出来。为了解决这个问题，我们可以使用一个特殊的技巧（hack）：每当我们想要向某个类 C​ 中添加一个新方法时，我们使用如下这种结构方式来实现。

``` py
class C(C):
    def new_method(self, args):
        pass
```

这看起来像是将 C​ 定义为了它自身的子类，这在逻辑上是说不通的 —— 但实际上，它所做的是：将一个新的类 C 定义为旧类 C 的子类，然后用这个新的类 覆盖（shadow）掉原来旧的 C 定义。

通过这种方式，我们最终得到的是一个包含了新方法 new_method() 的 C 类，而这正是我们想要的。（不过需要注意的是，之前已经创建的 C 类对象仍然基于旧的 C 定义，因此如果它们需要使用新方法，就必须重新构建。）

利用这个技巧，我们现在就可以添加一个 mutate() 方法，这个方法实际上会调用前面提到的那个 mutate() 函数。将 mutate() 实现为一个方法​ 是很有用的，尤其是当我们后续想要扩展 MutationFuzzer 类（比如增加更多功能或变异策略）时，这样我们就可以直接在类内部调用该方法，而不必每次都去调用外部的函数。

``` py
class MutationFuzzer(MutationFuzzer):
    def mutate(self, inp: str) -> str:
        return mutate(inp)
```

让我们回到我们的核心策略：**尽可能提高种群（population）中输入的多样性，以扩大覆盖范围**。

首先，我们来创建一个方法 create_candidate()，它的作用是：

- 从当前种群（也就是 self.population，即我们已经有的输入集合）中随机选取一个输入；
- 然后对这个输入应用介于 min_mutations 和 max_mutations 之间的若干次变异操作（mutation steps）；
- 最终返回经过这些变异后得到的新输入。

换句话说，这个方法会基于现有的某个“种子”输入，通过多次随机变异，生成一个新的、可能有所不同的输入，从而为我们的测试输入池引入更多变化，提升测试的覆盖范围。

然而，输入的多样性越高，也就意味着其中出现无效输入（invalid input）的风险也越大。

要想成功，关键在于对这些变异进行引导（guiding these mutations）​ —— 也就是说，我们要保留那些特别有价值的变异结果。

## Guiding by Coverage

为了尽可能覆盖更多的功能，我们可以依赖两种方式：一种是基于程序的明确规范（specified functionality），另一种是基于程序的实际实现（implemented functionality），正如我们在“覆盖率（Coverage）”那一章中所讨论的那样。不过，就目前而言，我们暂不假设程序的行为有明确的规范（尽管如果能有一个规范当然会更好）。但我们假设被测程序是存在的，而且我们可以利用程序本身的结构来指导测试用例的生成。

由于测试的过程本质上就是运行程序本身，因此我们总是可以获取到程序运行时的一些信息 —— 至少也能知道一个测试用例是通过（pass）还是失败（fail）。此外，由于覆盖率（coverage）也常常被用作衡量测试质量的一个指标，所以我们这里也假设我们能够获取每次测试运行所达到的覆盖率信息。

那么问题来了：我们如何利用这些覆盖率信息来指导测试用例的生成呢？

一个特别成功的思路，已经在广受欢迎的一款模糊测试工具中得到了实际应用，这款工具叫做 American Fuzzy Lop，通常简称为 AFL。

与上面我们讨论的例子类似，AFL 也会对那些“成功”的测试用例进行演化（进化）​ —— **但在 AFL 的语境中，“成功”指的是 发现了程序执行中的一条新路径（a new path through the program execution）。也就是说，AFL 会持续对那些已经发现过新执行路径的输入进行变异；而一旦某个输入又发现了另外一条新路径，那么这个输入也会被保留下来，作为后续变异的基础**。参考[AFL Technical](../../afl/technical_details.md)

那么，接下来，我们就来构建这样一个策略。我们首先引入一个 Runner 类，它的作用是捕获某个函数在运行时的覆盖率信息。我们先从定义一个 FunctionRunner 类​ 开始：

``` py
http_runner = FunctionRunner(http_program)
http_runner.run("https://foo.bar/")
```

现在，我们可以对 FunctionRunner 类​ 进行扩展，使其也能够测量程序运行时的覆盖率。在执行完 run() 方法之后，我们可以通过调用 coverage() 方法，来获取上一次运行所达到的覆盖率信息。

现在，我们来看主类（核心类）的实现。在这个类中，我们会维护两个主要的东西：

- population（种群）：也就是我们当前已经拥有的、用于测试的输入集合；
- coverages_seen（已见过的覆盖率集合）：记录下我们在之前的测试中已经获得过的各种覆盖率情况，用来判断某次运行是否带来了新的覆盖路径。

此外，我们还定义了一个辅助函数 fuzz()，它的作用是：

- 接收一个输入（input）；
- 使用给定的目标函数 function()​ 对该输入进行运行（调用）；
- 然后检查这次运行所得到的 覆盖率（coverage）​ 是否是新的（即：是否尚未出现在 coverages_seen 集合中）；
- 如果是新的覆盖率，那么就把这个输入加入到种群（population）中，同时把这次获得的覆盖率也加入到 coverages_seen 中，表示这个覆盖率已经被发现过了。

``` py
seed_input = "http://www.google.com/search?q=fuzzing"
mutation_fuzzer = MutationCoverageFuzzer(seed=[seed_input])
mutation_fuzzer.runs(http_runner, trials=10000)
mutation_fuzzer.population
```

通过这样的操作，能够使得每一个输入都是有效的，并且每一个输入都具有不同的覆盖率。这些输入是通过各种不同的组合产生的，包括：协议方案（schemes）、路径（paths）、查询参数（queries）以及片段（fragments）等不同部分的变异组合。

这个策略的一个优点是：当它被应用到更大的程序上时，它能够愉快地（即自动地、持续地）一条路径接着一条路径地进行探索​ —— 从而一个功能接着一个功能地覆盖程序的各个部分。

**而我们所需要做的，仅仅是找到一种方法来捕获程序运行时的覆盖率信息（coverage）。**
