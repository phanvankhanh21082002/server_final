Bước 1: Download and Activate Virtual Environment
sudo apt-get install -y python3-venv
python3 -m venv /home/venv
source /home/venv/bin/activate

Bước 2: Cài đặt jadx và java
sudo apt-get install -y openjdk-17-jdk
Download jadx 1.3.0 ở https://github.com/skylot/jadx/releases?page=2
mkdir jadx
mv jadx-1.3.0.zip jadx
cd jadx
unzip jadx-1.3.0.zip
rm jadx-1.3.0.zip
sudo ln -s $(pwd)/bin/jadx /usr/local/bin/jadx
sudo ln -s $(pwd)/bin/jadx-gui /usr/local/bin/jadx-gui

Bước 3: Cài đặt SDK
mkdir -p $HOME/Android/Sdk/cmdline-tools/latest
cd $HOME/Android/Sdk/cmdline-tools/latest
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip -O commandlinetools.zip
unzip commandlinetools.zip
rm commandlinetools.zip
mv cmdline-tools/* .
rm -r cmdline-tools/
nano ~/.bashrc
# add lines into file .bashrc
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin
export PATH=$PATH:$ANDROID_HOME/platform-tools
export PATH=$PATH:$ANDROID_HOME/build-tools/34.0.0
####################
source ~/.bashrc
sdkmanager --sdk_root=$ANDROID_HOME "build-tools;34.0.0"

Bước 4: Chạy file requirment.sh trong folder code_static
./requirement.sh

Bước 5: Tạo folder uploads ở trong folder server_final
cd server_final
mkdir uploads
