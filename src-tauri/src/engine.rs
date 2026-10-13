pub(crate) mod func;
pub(crate) mod python;
pub(crate) mod scanner;
pub(crate) mod utils;

extern crate notify;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
//use std::path::PathBuf;

const FOLDER: &str = "C:\\Users\\muhds\\Desktop\\Test";

pub fn engine() {
    let path = Path::new(FOLDER);

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();
    if utils::check_db() == false {
        utils::create_db();
    }

    watcher
        .watch(path, RecursiveMode::Recursive)
        .expect("Failed to watch directory");

    loop {
        match rx.recv() {
            Ok(event) => {
                let event_string = format!("{:?}", event);
                let event_vec: Vec<&str> = event_string.split(",").collect();
                utils::add_noti(
                    event_vec[1].split("\"").collect::<Vec<&str>>()[1],
                    event_vec[0].split(" ").collect::<Vec<&str>>()[0],
                );
                if event_vec[0].contains("Create") {
                    println!(
                        "File created: {:?}",
                        event_vec[1].split("\"").collect::<Vec<&str>>()[1]
                    );
                    /*let file = event_vec[1].split("\"").collect::<Vec<&str>>()[1];
                    let file_path = PathBuf::from(file);
                    check if file is malware
                    //let result = python::identify(file_path.to_str().unwrap()).unwrap();
                    if result == "Malicious" {
                        println!("Malware detected: {:?}", file);
                        utils::add_file(file, "Malware");
                        remediate(file);
                    } */
                }
            }
            Err(e) => {
                println!("watch error: {:?}", e);
            }
        }
    }
}
/*
fn remediate(filepath: &str) {
    //check if file is in quarantine
    let dir = Path::new(FOLDER);
    let path = dir.join(filepath);
    let quarantine_path = Path::new("C:\\neural-av\\Quarantine");
    let quarantine_file = quarantine_path.join(filepath);
    if quarantine_file.exists() {
        //restore file
        utils::restore_file(quarantine_file.to_str().unwrap());
        //delete file from quarantine
        let _ = utils::delete_file(quarantine_file.to_str().unwrap());
    }

    //run inference
    let result = python::classify(&filepath).unwrap();

    //check if file is malware
    if result == "Malware" {
        //delete file
        let _ = utils::delete_file(path.to_str().unwrap());
    } else {
        //restore file
        utils::restore_file(path.to_str().unwrap());
    }

    //delete file from quarantine
    let _ = utils::delete_file(quarantine_file.to_str().unwrap());
}

*/