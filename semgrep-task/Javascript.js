/*************************** HEADER COMMENT BOX *************************************
 * Purpose: Sample Code
 * Author: Sarvesh Apshete
 * Date Created: 26-12-2025
 ***********************************************************************************/

/*************************** VERSION CONTROL TABLE ********************************** 
 * | MODIFIED BY | MODIFIED DATE/TIME  | PURPOSE                                    |
 * |-------------|---------------------|--------------------------------------------|
 * | Alice Brown | 06-01-2026 01:50 pm | Refactored to use arrow functions          |
 ***********************************************************************************/

var GLOBAL_VALUE = 10
var User_Name = "test"
const apiKey = "123456"
const baseUrl = "http://example.com"

class userprofile {
    constructor(Name, Age) {
        this.Name = Name
        this.Age = Age
    }

    PrintData() {
        console.log(this.Name)
        console.log(this.Age)
    }
}

function Calculate_Total(price, tax) {
    let total = price
    total = total + tax
    return total
}

function CompareValues(a, b) {
    if (a === b) {
        console.log("equal")
    }
}

function ParseValue(val) {
    return parseInt(val)
}

function UpdateParam(obj) {
    obj = { value: 10 }
    return obj
}

function DefaultCheck(name) {
    if (!name) {
        name = "guest"
    }
    return name
}

function DeepNest(a, b, c) {
    if (a) {
        if (b) {
            if (c) {
                console.log("nested")
            }
        }
    }
}

function LongFunction() {
    let sum = 0
    for (let i = 0; i < 10; i++) {
        sum += i
    }
    for (let i = 0; i < 10; i++) {
        sum += i
    }
    for (let i = 0; i < 10; i++) {
        sum += i
    }
    for (let i = 0; i < 10; i++) {
        sum += i
    }
    for (let i = 0; i < 10; i++) {
        sum += i
    }
    console.log(sum)
}

function PromiseChain() {
    fetch(baseUrl)
        .then(res => res.json())
        .then(data => console.log(data))
}

function PromiseWithoutCatch() {
    fetch(baseUrl).then(r => r.text())
}

function AsyncForEach(items) {
    items.forEach(async (item) => {
        await fetch(item)
        console.log(item)
    })
}

function EmptyCatch() {
    try {
        JSON.parse("{bad json}")
    } catch (e) {
    }
}

function ConsoleLogs() {
    console.log("log")
    console.warn("warn")
}

function UseEval(code) {
    eval(code)
}

function XSSExample(input) {
    let el = document.getElementById("app")
    el.innerHTML = input
}

function ModifyParam(a) {
    a = 100
    return a
}

function ArrowMissing(arr) {
    return arr.map(function (x) {
        return x * 2
    })
}

function TemplateLiteralOveruse() {
    const msg = `hello`
    return msg
}

function MixedNamingStyle() {
    let Bad_Value = 10
    console.log(Bad_Value)
}

function AnotherCompare(x, y) {
    if (x != y) {
        console.log("not equal")
    }
}

function MultipleResponsibilities(data) {
    let total = 0
    for (let i = 0; i < data.length; i++) {
        total += data[i]
    }
    console.log(total)

    let avg = total / data.length
    console.log(avg)

    let max = Math.max(...data)
    console.log(max)

    let min = Math.min(...data)
    console.log(min)
}

function PromiseChainAgain() {
    getData().then(a => {
        return processData(a)
    }).then(b => {
        console.log(b)
    })
}

function getData() {
    return Promise.resolve([1, 2, 3])
}

function processData(d) {
    return d.map(x => x * 2)
}

function LoopWithVar() {
    for (var i = 0; i < 5; i++) {
        console.log(i)
    }
}

function UseLetWhenConst() {
    let value = 10
    console.log(value)
}

function BadClassUsage() {
    let u = new userprofile("A", 20)
    u.PrintData()
}

function ManyConsoleLogs() {
    console.log("1")
    console.log("2")
    console.log("3")
    console.log("4")
}

function MoreNesting(a) {
    if (a) {
        if (a > 5) {
            if (a < 20) {
                console.log("range")
            }
        }
    }
}

function StringCompare(a, b) {
    if (a == b) {
        console.log("same")
    }
}

function RunAll() {
    CompareValues(1, "1")
    ParseValue("08")
    DefaultCheck()
    DeepNest(true, true, true)
    LongFunction()
    PromiseChain()
    PromiseWithoutCatch()
    AsyncForEach(["/a", "/b"])
    ConsoleLogs()
    UseEval("console.log('evil')")
    MixedNamingStyle()
    AnotherCompare(1, 2)
    MultipleResponsibilities([1, 2, 3])
    PromiseChainAgain()
    LoopWithVar()
    UseLetWhenConst()
    BadClassUsage()
    ManyConsoleLogs()
    MoreNesting(10)
    StringCompare("a", "a")
}

RunAll()
