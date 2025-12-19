import React from 'react'
import { NavLink } from 'react-router-dom'
import NotificationList from '../../components/Notification/NotificationList'
import { FaPlus } from 'react-icons/fa'

export default function Notification() {
  return (
    <div class='bg-[#F7F7F7] h-screen px-4 py-10 lg:px-10 ' >
    <div className='flex items-center  justify-between' >
      <div>
        <NavLink  className='font-semibold text-[24px] md:mb-5 leading-[29px] flex items-center' > Push Notifications</NavLink>
      </div>
      <div>
      <NavLink to={"/createnotification"} className={`flex text-sm md:w-[203px] font-semibold text-center bg-[#0A8A33] text-white h-[44px] flex items-center justify-center rounded-[8px] font-semibold px-2 md:px-4 mx-5 py-2 `}> <FaPlus className='mr-2 text-sm'  /> Create Notification</NavLink>
      </div>
    </div>
     <NotificationList/>
</div>
  )
}
