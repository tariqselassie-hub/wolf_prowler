#!/bin/bash
# consolidate_dashboard.sh

echo "=== Consolidating Dashboard Assets to 'static/' ==="

# 1. Ensure target exists
mkdir -p static/css static/js static/images

# 2. Move from src/dashboard (excluding Rust files)
if [ -d "src/dashboard" ]; then
    echo "Moving HTML files from src/dashboard/ to static/..."
    mv src/dashboard/*.html static/ 2>/dev/null
    
    echo "Moving CSS/JS/Images from src/dashboard/ to static/..."
    mv src/dashboard/*.css static/css/ 2>/dev/null
    mv src/dashboard/*.js static/js/ 2>/dev/null
    mv src/dashboard/*.png static/images/ 2>/dev/null
    mv src/dashboard/*.svg static/images/ 2>/dev/null
    
    # Handle nested static folder if it exists (common source of confusion)
    if [ -d "src/dashboard/static" ]; then
        echo "Merging src/dashboard/static/ into static/..."
        cp -r src/dashboard/static/* static/
        rm -rf src/dashboard/static
    fi
    
    echo "✅ Assets moved. Rust files (.rs) in src/dashboard/ preserved."
else
    echo "src/dashboard/ not found, skipping."
fi

# 3. Merge from wolf_web/static if it exists
if [ -d "wolf_web/static" ]; then
    echo "Merging assets from wolf_web/static/ into static/..."
    cp -r wolf_web/static/* static/ 2>/dev/null
    echo "✅ wolf_web/static assets merged."
fi

echo -e "\n=== Consolidation Complete ==="
echo "ACTION REQUIRED: Update your main.rs to serve the 'static' directory:"
echo '   .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))'