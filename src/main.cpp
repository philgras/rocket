#include<iostream>
#include<string>

struct A {
    virtual ~A(){
        std::cout<<"A"<<std::endl;
    }
};

struct B : A {
    ~B(){
        std::cout<<"B"<<std::endl;
    }
};

struct C : B {
    virtual ~C(){
        std::cout<<"C"<<std::endl;
    }
};

int main(int nargs, char** vargs){

    C b;
    for(int i = 0; i < nargs; ++i){
        std::cout<<vargs[i]<<std::endl;
    }
}
