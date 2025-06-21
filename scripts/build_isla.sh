cd isla/
echo " Applying patch! "
git apply ../patches/isla.patch || exit 
echo " Building Isla..." 
cargo build --release
cd ../
cp configs/riscv64.toml isla/configs/
