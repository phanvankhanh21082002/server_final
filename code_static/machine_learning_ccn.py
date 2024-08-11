import os
import sys
import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator, img_to_array, load_img
from tensorflow.keras.models import load_model
from PIL import Image
import zipfile
import shutil

# Constants
EXTRACT_PATH = '../extract_apk_ML'
IMAGE_SIZE = (64, 64)
BATCH_SIZE = 32
MODEL_PATH = '../code_static/malware_classification_model.h5'  # Model path set directly

# Function to extract APK file
def extract_apk(apk_path, extract_path):
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

# Function to convert DEX files to images
def dex_to_image(dex_file, image_path):
    with open(dex_file, 'rb') as f:
        data = f.read()
    data = bytearray(data)
    np_array = np.array(data, dtype=np.uint8)
    size = int(len(np_array) ** 0.5)
    if size * size != len(np_array):
        np_array = np_array[:size * size]
    np_array = np_array.reshape((size, size))
    img = Image.fromarray(np_array, 'L')
    img = img.resize(IMAGE_SIZE)
    img.save(image_path)

# Function to process all DEX files and convert to images
def process_apk_to_images(extract_path, image_dir):
    if not os.path.exists(image_dir):
        os.makedirs(image_dir)
    for root, _, files in os.walk(extract_path):
        for file in files:
            if file.endswith('.dex'):
                dex_path = os.path.join(root, file)
                image_path = os.path.join(image_dir, f"{file}.png")
                dex_to_image(dex_path, image_path)

# Function to prepare image for prediction
def prepare_image(image_path):
    img = load_img(image_path, target_size=IMAGE_SIZE)
    img_array = img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0)
    img_array /= 255.0
    return img_array

# Main function to load model and make prediction
def main(apk_path):
    # Step 1: Extract APK file
    extract_apk(apk_path, EXTRACT_PATH)

    # Step 2: Convert DEX files to images
    image_dir = os.path.join(EXTRACT_PATH, 'images')
    process_apk_to_images(EXTRACT_PATH, image_dir)

    # Step 3: Load trained model
    model = load_model(MODEL_PATH)

    # Step 4: Prepare and predict
    predictions = []
    for image_file in os.listdir(image_dir):
        image_path = os.path.join(image_dir, image_file)
        img_array = prepare_image(image_path)
        prediction = model.predict(img_array)
        predictions.append((image_file, prediction[0][0]))

    # Step 5: Delete temporary extracted files
    shutil.rmtree(EXTRACT_PATH)

    # Step 6: Print predictions
    for image_file, prediction in predictions:
        label = 'Malware' if prediction > 0.5 else 'Clean'
        print(f"File: {image_file}, Prediction: {prediction:.4f}, Label: {label}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python your_script.py <path_to_apk>")
        sys.exit(1)
    APK_PATH = sys.argv[1]
    main(APK_PATH)
