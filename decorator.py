
def out_function():
    print("I am outside function")

    def inner_function():
        print ("I am inside function")
        print(2)
    return inner_function()


result = out_function()

