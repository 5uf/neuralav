use std::path::{PathBuf,Path};
use hex::encode;
use std::fs::{self, File};
use std::io::Read;

pub fn convert(file_path: &PathBuf) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut file_data = Vec::new();
    file.read_to_end(&mut file_data)?;
    let hex_data = encode(&file_data);
    Ok(hex_data)
}

pub fn utf_convert(file_path: &PathBuf) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut binary_data = Vec::new();
    file.read_to_end(&mut binary_data)?;
    let hex_data = encode(&binary_data);
    let (cow, _, _) = encoding_rs::UTF_16LE.decode(&hex_data.as_bytes());
    let result = divide_text(&cow);
    Ok(result.join(" "))
}

pub fn divide_text(text: &str) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    let mut temp = String::new();
    let mut count = 0;
    for c in text.chars() {
        if count == 512 {
            result.push(temp);
            temp = String::new();
            count = 0;
        }
        temp.push(c);
        count += 1;
    }
    result.push(temp);
    result
}

//find file in path hwile traversing
pub fn traverse_path(start_path: &str, _file: &str) -> PathBuf {
    let start_path = start_path.to_string();
    let dir = Path::new(&start_path);
    //get permission
    let metadata = fs::metadata(dir).unwrap();
    let permissions = metadata.permissions();
    let mut entries = fs::read_dir(dir).unwrap();
    if   permissions.readonly() {
        println!("Permission denied");
    }
    let mut _result: Vec<PathBuf> = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            let temp = traverse_path(path.to_str().unwrap(), _file);
            if temp != PathBuf::from("") {
                return temp;
            }
        } else {
            let file_name = path.file_name().unwrap().to_str().unwrap();
            if file_name == _file {
                return path;
            }
        }
    }
    PathBuf::from("")
}

//find all files in path while traversing
pub fn traverse_all(start_path: &str) -> Vec<PathBuf> {
    let start_path = start_path.to_string();
    let dir = Path::new(&start_path);
    //get permission
    let metadata = fs::metadata(dir).unwrap();
    let permissions = metadata.permissions();
    let mut entries = fs::read_dir(dir).unwrap();
    if   permissions.readonly() {
        println!("Permission denied");
    }
    let mut result: Vec<PathBuf> = Vec::new();
    while let Some(entry) = entries.next() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            let mut temp = traverse_all(path.to_str().unwrap());
            result.append(&mut temp);
        } else {
            result.push(path);
        }
    }
    result
    
}

