# !/usr/bin/sh
make O=out ARCH=arm64 CROSS_COMPILE=~/aarch64gcc/bin/aarch64-linux-android- merge_hi6250_defconfig > defconfig.log

if [ $? -eq 0 ]; then
	TIME_CURR=$(TZ=":Asia/Kolkata" date +"%d.%m.%Y-%T")
	telegram-send $TIME_CURR" - Make defconfig successful"
else
	TIME_CURR=$(TZ=":Asia/Kolkata" date +"%d.%m.%Y-%T")
	telegram-send $TIME_CURR" - Error in make defconfig building"
fi

telegram-send -f defconfig.log

make O=out ARCH=arm64 CROSS_COMPILE=~/aarch64gcc/bin/aarch64-linux-android- -j200 > defconfig.log > build.log
if [ $? -eq 0 ]; then
	TIME_CURR=$(TZ=":Asia/Kolkata" date +"%d.%m.%Y-%T")
	telegram-send $TIME_CURR" - Build successful"
else
	TIME_CURR=$(TZ=":Asia/Kolkata" date +"%d.%m.%Y-%T")
	telegram-send $TIME_CURR" - Error in building"
fi

telegram-send -f build.log

if [ $? -eq 0 ]; then
	./tools/mkbootimg --kernel out/arch/arm64/boot/Image.gz --base 0x00400000 --cmdline "loglevel=4 coherent_pool=512K page_tracker=on slub_min_objects=12 unmovable_isolate1=2:192M,3:224M,4:256M printktimer=0xfff0a000,0x534,0x538 androidboot.selinux=enforcing buildvariant=user" --tags_offset 0x07A00000 --kernel_offset 0x00080000 --ramdisk_offset 0x10000000 --os_version 9 --os_patch_level 2019-04-01  --output kernelvv.img
	id=$(gdrive upload kernelvv.img --share)
	TOKEN=`echo $id | grep -Po 'Uploaded \K.*?(?= at)'|tr -d '\n\r'`
	Link=`echo $id |  grep -Po 'anyone at \K.*$'|tr -d '\n\r'`
	telegram-send 'Build Image Successful
	Token:'$TOKEN'
	Link: '$Link
fi

rm -rf kernelvv.img defconfig.log build.log
rm -rf out/
make mrproper
make clean

