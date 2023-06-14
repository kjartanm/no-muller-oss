import path from 'path';


/** @type {import('vite').UserConfig} */
const config = {
    build: {
        lib: {
            entry: path.resolve(__dirname, 'src/main.js'),
            name: 'MyLib',
            formats: ['es'],
            fileName: 'index',
        },
    },
}

export default config