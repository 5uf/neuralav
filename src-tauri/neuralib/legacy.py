import torch
from transformers import AutoTokenizer

def identify(hex):  
    try:
        # get path to model and tokenizer from C: di
        model_path = 'C:/neural-av/identifibert.pt'
        tokenizer_path = 'C:/neural-av/tokenizer'
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        model = torch.load(model_path, map_location=torch.device('cpu'))
        tokens = tokenizer(hex, padding=True, truncation=True, return_tensors='pt')
        print(tokens)
        with torch.no_grad():
            outputs = model(tokens['input_ids'], tokens['attention_mask'])
        return "Benign" if torch.argmax(outputs[0], dim=1).numpy()[0] == 1 else "Malicious"
    except Exception as e:
        return e

def classify(hex):
    try:
        model_path = 'C:/neural-av/classifibert.pt'
        tokenizer_path = 'C:/neural-av/tokenizer'
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        model = torch.load(model_path, map_location=torch.device('cpu'))
        tokens = tokenizer(hex, padding=True, truncation=True, return_tensors='pt')
        with torch.no_grad():
            outputs = model(tokens['input_ids'], tokens['attention_mask'])
        return str(outputs[0].tolist()[0])
    except Exception as e:
        return e
    
def sortclassify(hex):
    try:
        #remove double quotes from array
        array = array.replace('"', '')
        #split array into list
        array = array.split(',')
        #convert list to int
        array = [int(i) for i in array]
        #sort list
        array.sort()
        #find the highest number in the list and return
        return array[-1]
    except Exception as e:
        return e
    
def main():
    #get hex from user
    hex = "0x4d5a90000300000004000000ffff0000b800000000000000400000000000000000"
    #call identify function
    identify(hex)
    #call classify function
    classify(hex)
    #call sortclassify function
    sortclassify(hex)
    #print results
    print(identify(hex))
    print(classify(hex))
    print(sortclassify(hex))

if __name__ == '__main__':
    main()


  
