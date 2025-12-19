import React from 'react'
import { NavLink } from 'react-router-dom'
import { IoMdArrowBack } from "react-icons/io";
import UpdatePasswordModal from '../../components/Auth/UpdatePasswordModal';

export default function EditProfile() {
    
    return (
        <div class='bg-[#F7F7F7] h-[90vh] py-5 px-5 ' >
        <NavLink to={'/profile'} className='font-semibold text-[24px] leading-[29px] flex items-center' > <IoMdArrowBack size={25} className='mr-2' /> Edit Profile</NavLink>
        <div class='bg-[#FFFFFF] border rounded-[10px] border-[#E4E4E4] mt-6 lg:py-10 lg:px-10' >
            <div class='bg-[#F9FAFB] rounded-[10px] border border-[#E4E4E4] py-3 px-3 lg:py-10 lg:px-10'>
                <div className='flex items-center' >
                    <img src="/person.webp" class='rounded-[50%] mt-2 cursor-pointer w-[50px] h-[50px]' alt="" />
                    
                    <label htmlFor="changeprofile" className='ml-3 font-semibold text-base underline cursor-pointer'>  Change</label>
                    <input type="file" className='hidden' id='changeprofile' />
                </div>
                <form onSubmit={(e)=>e.preventDefault()} >

                    <div class='mt-5 grid grid-cols-1 gap-5  lg:grid-cols-2' >
                        <div className='mb-3' >
                            <label class=' text-[13px] mb-1 font-semibold leading-[16.94px] ' >Name</label>
                            <input type="text" id="base-input" class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  " required  placeholder='Full Name' />
                        </div>
                        <div className='mb-3' >
                            <label class=' text-[13px] mb-1 font-semibold leading-[16.94px] ' >Email</label>
                            <input type="email" id="base-input" class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  " required  placeholder='Email Address' />
                        </div>
                        <div >
                            <label class=' text-[13px] mb-1 font-semibold leading-[16.94px] ' >Contact No</label>
                            <input type="tel" id="base-input" class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg  h-[60px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]  " required  placeholder='Contact No' />
                        </div>
                        <div >
                            <label class=' text-[13px] mb-1 font-semibold leading-[16.94px] ' >Address</label>
                            <input type="email" id="base-input" class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg h-[60px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  " required  placeholder='Address' />
                        </div>
                        <div>
                        <button type="submit" class="text-white bg-[#0A8A33]  rounded-lg  w-[150px] h-[50px]  px-5 py-2.5 text-center">Save</button>
                        </div>
                    </div>
                </form>
            </div>
            <div>
            </div>
        </div>
        <UpdatePasswordModal />

    </div>
    )
}
