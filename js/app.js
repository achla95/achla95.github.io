const navSlide = () =>{
    const burger = document.querySelector('.burger');
    const nav = document.querySelector('.nav-links');
    const navLinks = document.querySelectorAll('.nav-links li');

    burger.addEventListener('click', () =>{
            //toggle nav
        nav.classList.toggle('nav-active');
        nav.style.backgroundColor = '#6D4AFF';
           //animate links
    navLinks.forEach((link, index) =>{
        if (link.style.animation){
            link.style.animation = '';
        } else{
            link.style.animation = `navLinkFade 0.5s ease forwards ${index / 7 + 0.3}s`;
        }
    });
    //burger animation
    burger.classList.toggle('toggle')
    });
 
}

const filterList = () => {
    document.querySelector('.search-input').addEventListener('keyup', ()=>{
        const search = document.querySelector('.search-input');
        const filter = search.value.toLowerCase();
        const listItem = document.querySelectorAll('.blocks');
    
        listItem.forEach((item) =>{
            content = item.textContent;
            if (content.toLowerCase().includes(filter)){
                item.style.display = '';
            } else{
                item.style.display = 'none';
            }
        });
    });

}

const darkLightTheme = () => {
    const chk = document.getElementById('chk');

chk.addEventListener('change', () => {
	document.querySelector('.nav-bar').classList.toggle('dark');
	document.body.classList.toggle('dark');
    document.querySelectorAll('.blocks').forEach((block) =>{block.classList.toggle('dark')});
    document.querySelectorAll('.blocks .title').forEach((title) => {title.classList.toggle('dark')});
    document.querySelectorAll('.title a').forEach((title) => {title.classList.toggle('dark')});
    document.querySelectorAll('article p').forEach((text) => {text.classList.toggle('dark')});
    document.querySelectorAll('.blocks .description').forEach((description) => {description.classList.toggle('dark')});
    document.querySelectorAll('article h2').forEach((title) => {title.classList.toggle('dark')});
    document.querySelectorAll('.articles-content p').forEach((p) => {p.classList.toggle('dark')});
    document.querySelectorAll('.articles-content h1').forEach((h) => {h.classList.toggle('dark')});
    document.querySelectorAll('.container .info').forEach((info) => {info.classList.toggle('dark')});
});
}

darkLightTheme();
navSlide();
filterList();