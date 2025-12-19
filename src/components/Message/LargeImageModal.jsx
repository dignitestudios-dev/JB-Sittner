import React, { useContext, useEffect } from "react";
import { MyContext } from "../../context/GlobalContext";
import { Swiper, SwiperSlide } from "swiper/react";
// Import Swiper styles
import "swiper/css";
import "swiper/css/pagination";
import "swiper/css/navigation";

// Import required modules
import { Keyboard, Pagination, Navigation } from "swiper/modules";
import { IoIosCloseCircleOutline } from "react-icons/io";



export default function ViewImage() {
  const { viewImage, setIviewImage, ModalImageUrl } = useContext(MyContext);

  return (
    <>
      {viewImage ? (
        <>
          <div className="justify-center px-4 bg-view-image items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-[999999999] outline-none focus:outline-none">
            <div className="relative w-[100%] md:w-[650px] my-6 mx-auto max-w-4xl">
              {/* Close button */}
              <div className="flex justify-end bg-white px-2 py-2">
                <button onClick={() => setIviewImage(false)}>
                  <IoIosCloseCircleOutline size={30} />
                </button>
              </div>
              <div className="border-0 h-[300px] md:h-[500px] w-[100%] rounded-lg shadow-lg relative flex flex-col w-full bg-white outline-none focus:outline-none">
                {/* Swiper component */}
                <Swiper
                  slidesPerView={1}
                  spaceBetween={30}
                  keyboard={{
                    enabled: true,
                  }}
                  simulateTouch={false} 
                  grabCursor={false} 
                  allowTouchMove={false}
                  pagination={false}
                  navigation={true}
                  modules={[Keyboard, Pagination, Navigation]}
                  className="mySwiper"
                >
                  {ModalImageUrl.map((img, i) => (
                   !img?.url?.includes(".pdf") && !img?.url?.includes(".xlsx")&&(                      
                    <SwiperSlide key={i}>
                   
                    </SwiperSlide>
                    )
                  ))}
                </Swiper>
              </div>
            </div>
          </div>

          {/* Background overlay */}
          <div className="opacity-25 fixed inset-0 z-40 bg-black"></div>
        </>
      ) : null}
    </>
  );
}
