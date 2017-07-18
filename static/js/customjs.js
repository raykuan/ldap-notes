/**
 * Created by root on 7/18/17.
 */

// $("document").ready(function () {
//     $(".list-group a").click(function () {
//         $(".list-group a").removeClass("active");//首先移除全部的active
//         $(this).addClass("active");//选中的添加acrive
//     });
// });


// $('#navleft').find("a").each(function(){
//         var a = $(this)[0].href;
//         if( a === String(window.location)){
//             $(this).addClass("active");
// }
//     });


// $(document).ready(function () {
//     $('#navleft').click(function (e) {
//         e.preventDefault();
//         $('ul.nav > li').removeClass('active');
//         $(this).addClass('active');
//     });
// });



// $(function (){
//     $('#navleft').find("a").each(function(){
//
//         var a = $(this).find("a")[0];
//         // if ($(a).attr("href") === location.pathname){
//         if ($(a).attr("href") === String(window.location)){
//             $(this).removeClass('active');
//         }else {
//            $(this).addClass("active");
//         }
//     });
// });

// onload = function () {
//     function removeActiveClass(node) {
//         node.removeClass = 'active';
//         // node.className = '';
//     }
//
//     document.querySelector('div[id=navleft]').onclick = function (e) {
//         Array.prototype.forEach.call(document.querySelectorAll('div[id=navleft] > a'), removeActiveClass);
//         var target = e.target;
//         target.addClass = 'active';
//     }
// };

//
//
// $(function () {
//     $("#navleft").find("a").each(function () {
//         var a = $(this).find("a:first")[0];
//
//         if ($(a).attr("href") === location.pathname) {
//             $(this).addClass("active");
//         } else {
//             $(this).removeClass("active");
//         }
//     });
// });


// $('#navleft').find('a').each(function () {
//         if (this.href == document.location.href || document.location.href.search(this.href) >= 0) {
//             $(this).addClass('active'); // this.className = 'active';
//         }
// });
//
// $(function(){
//     $("#navleft").find('a').on("click",function(e){
//         var tmp = $(this).attr("href");
//         if(tmp == location.pathname){
//
//         }
//         $(".lily").attr("src",source);
//         e.preventDefault();
//     })
// });
//
// $(function () {
//     $("#navleft").find("a").each(function () {
//         var a = $(this).find("a:first")[0];
//         if ($(a).attr("href") === window.location.pathname) {
//             $(this).addClass("active");
//         } else {
//             $(this).removeClass("active");
//         }
//     });
// });

//
// $(document).ready(function () {
//    $('div.navleft > a').click(function (e) {
//       e.preventDefault();
//       $('div.navleft > a').removeClass('active');
//       $(this).addClass('active');
//    });
// });
