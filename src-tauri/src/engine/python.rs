use cpython::{PyResult, Python, PyObject, ObjectProtocol};
use std::string::String;


pub fn identify(test: &str) -> PyResult<String> {
    let gil = Python::acquire_gil();
    let python = gil.python();
    let python_module = python.import("neuralib")?;
    let python_function: PyObject = python_module.get(python, "identify")?.extract(python)?;
    let result = python_function.call(python, (test,), None)?;
    let result_string: String = result.extract(python)?;
    Ok(result_string)
}

pub fn classify(test: &str) -> PyResult<String> {
    let gil = Python::acquire_gil();
    let python = gil.python();
    let python_module = python.import("neuralib")?;
    let python_function: PyObject = python_module.get(python, "classify")?;
    let result = python_function.call(python, (test,), None)?;
    let result_string: String = result.extract(python)?;
    Ok(result_string)
}

/*
pub fn warmup() {
    let file = "C:\\neural-av\\test.txt";
    let _result = identify(file).unwrap();
    let _result = classify(file).unwrap();
    println!("Neural-AV created by MSA!");
}*/