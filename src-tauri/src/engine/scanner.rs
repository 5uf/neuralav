use std::{ path::{Path, PathBuf}, str::FromStr };
use tokenizers::tokenizer::{Result, Tokenizer};
use tract_onnx::prelude::*;

pub fn identify(text: &str) -> Result<Vec<f32>> {
    let model_dir = PathBuf::from_str("model/onnx-identifibert")?;
    let tokenizer = Tokenizer::from_file(Path::join(&model_dir, "tokenizer.json"))?;
    let tokenizer_output = tokenizer.encode(text, true)?;
    println!("Tokenized");
    let input_ids = tokenizer_output.get_ids();
    let attention_mask = tokenizer_output.get_attention_mask();
    let token_type_ids = tokenizer_output.get_type_ids();
    let length = input_ids.len();
    print!("Loading model...");
    let model = tract_onnx::onnx()
        .model_for_path(Path::join(&model_dir, "model.onnx"))?
        .into_optimized()?
        .into_runnable()?;
    
    let input_ids: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        input_ids.iter().map(|&x| x as i64).collect(),
    )?
    .into();
    let attention_mask: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        attention_mask.iter().map(|&x| x as i64).collect(),
    )?
    .into();

    let token_type_ids: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        token_type_ids.iter().map(|&x| x as i64).collect(),
    )?
    .into();
    println!("Loaded");
    let outputs = model.run(tvec!(
        input_ids.into(),
        attention_mask.into(),
        token_type_ids.into()
    ))?;
    let logits: &Tensor = &outputs[0];
    println!("Ran");
    let logits = logits.to_array_view::<f32>()?;
    let result = logits
        .outer_iter()
        .map(|row| row.iter().map(|&x| x).collect::<Vec<f32>>())
        .collect::<Vec<Vec<f32>>>();
    Ok(result[0].clone())
}

pub fn classify(text: &str) -> Result<Vec<f32>> {
    let model_dir = PathBuf::from_str("model/onnx-classifier")?;
    let tokenizer = Tokenizer::from_file(Path::join(&model_dir, "tokenizer.json"))?;
    let tokenizer_output = tokenizer.encode(text, true)?;
    let input_ids = tokenizer_output.get_ids();
    let attention_mask = tokenizer_output.get_attention_mask();
    let token_type_ids = tokenizer_output.get_type_ids();
    let length = input_ids.len();

    let model = tract_onnx::onnx()
        .model_for_path(Path::join(&model_dir, "model.onnx"))?
        .into_optimized()?
        .into_runnable()?;

    let input_ids: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        input_ids.iter().map(|&x| x as i64).collect(),
    )?
    .into();
    let attention_mask: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        attention_mask.iter().map(|&x| x as i64).collect(),
    )?
    .into();

    let token_type_ids: Tensor = tract_ndarray::Array2::from_shape_vec(
        (1, length),
        token_type_ids.iter().map(|&x| x as i64).collect(),
    )?
    .into();

    let outputs = model.run(tvec!(
        input_ids.into(),
        attention_mask.into(),
        token_type_ids.into()
    ))?;
    let logits: &Tensor = &outputs[0];
    let logits = logits.to_array_view::<f32>()?;
    let result = logits
        .outer_iter()
        .map(|row| row.iter().map(|&x| x).collect::<Vec<f32>>())
        .collect::<Vec<Vec<f32>>>();
    Ok(result[0].clone())
}

//receive Vec<f32> and return Malicious or Harmless
pub fn type_label(input: Vec<f32>) -> String {
    let mut max = 0.0;
    let mut index = 0;
    let labels = vec!["Harmless", "Malicious"];
    for i in 0..input.len() {
        if input[i] > max {
            max = input[i];
            index = i;
        }
    }
    let label = labels[index];
    return label.to_string();
}

/* 0-Virus, 1-Worm, 2-Trojan, 3-CryptoJacker, 4-Spyware, 
5-Ransomware, 6-Adware, 7-Botnet, 8-Rootkit */

pub fn class_label(input: Vec<f32>) -> String {
    let mut max = 0.0;
    let mut index = 0;
    let labels = vec!["Virus", "Worm", "Trojan", "CryptoJacker", "Spyware", "Ransomware", "Adware", "Botnet", "Rootkit"];
    for i in 0..input.len() {
        if input[i] > max {
            max = input[i];
            index = i;
        }
    }
    let class = labels[index];
    return class.to_string();
}